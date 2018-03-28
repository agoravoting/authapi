# This file is part of authapi.
# Copyright (C) 2016  Agora Voting SL <agora@agoravoting.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from django.db import connection
from django.db.models import Max
import json
import csv
import tempfile
from datetime import datetime
import hashlib

from api.models import AuthEvent, ACL, User
from timeit import default_timer as timer

#
# Imports barcelona census data into the database. The following steps are
# performed for each census row:
#
# 1) Creates new user
# 2) Creates user data linked to the user in 1) and the required event
# 3) Creates a "vote" permission for the required event
#
# Database loading is performed with postgresql COPY using intermediate
# csv files as input. These are temporary files generated incrementally
# before the COPY step. They will not be deleted automatically.
#
# Data mappings (capitalized fields are census input columns):
#
# user.password: hexdigest of sha256 of PASSWORD
#
# user.username: DNI _ CODI_POSTAL (no space)
#
# user.name: NOM
#
# user.lastname: COGNOM_1
#
# userdata.metadata.fullname: NOM COGNOM_1 COGNOM_2
#
# userdata.metadata: fields captured from input csv, as specified by the
# --metadata option (as well as including fullname)
#
# userdata.event_id: as specified by the combination of district_even_map
# parameter and DISTRICTE
#
# See example input census format and district_event_map format in
#
# api/management/commands/tests.py
#
#
# Assumptions
#
# The number of fields in the rows must match the header.
# All of the capitalized fields above must be present as columns.
# All of the fields mentioned in --metadata must be present as columns.
#
# If these are not met the script will bomb with a KeyError or ValueError.
#
#
# CLI usage described by
#
# manage.py import_bcn_census -h
#
#
# Testing
#
# manage.py test api.management.commands.tests.TestBcnImport
# --settings=authapi.test_settings --nocapture
#
# To specify the size of the load test, change
#
# LOAD_SIZE = 100000
#
# in api/management/commands/tests.py
#
class Command(BaseCommand):
    help = 'imports bcn census data'

    DELIMITER=';'

    # postgresql constants used when parsing COPY commands
    NULL = "\\N"
    FALSE="false"
    TRUE="true"

    USER_TABLE = "auth_user"
    USERDATA_TABLE = "api_userdata"
    ACL_TABLE = "api_acl"

    # constants for column values
    ACTIVE_STATUS = "act"
    VOTE_PERMISSION = "vote"
    AUTHEVENT_TYPE = "AuthEvent"

    # Unfortunately postgresql won't insert default values using
    # COPY unless you leave them out from the column list
    # (NULL does not work)
    # Therefore we must specify the columns explicitly in those tables
    # that use sequences for id's
    USERDATA_COPY_COLUMNS = '''("metadata", "status", "event_id", "user_id")'''
    ACL_COPY_COLUMNS = '''("perm", "user_id", "object_id", "object_type", "created")'''

    # the --verbose flag
    verbose = False

    def add_arguments(self, parser):
        parser.add_argument('census', nargs=1, type=str, help=
            'Path to census file in csv format')
        parser.add_argument('district_event_map', nargs=1, type=str, help=
            'Path to district event map in json format')
        parser.add_argument('--metadata', nargs='*', default=[], type=list,
            help= 'List of csv fields to capture as metadata, \
            will complain if not found')
        parser.add_argument('--verbose', nargs='?', const=True, help=
            'If present shows output csv row data as it is being generated')

    def handle(self, *args, **options):
        if options['verbose'] is not None:
            self.verbose = True

        # all created dates in the database will have this
        now_date = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        # the fields that will be captured as metadata in UserData entries
        metadata = options["metadata"]

        start_csv = timer()

        # Load the mapping that will control the assignment of
        # users to events, together with the DISTRICTE field
        with open(options['district_event_map'][0], 'r') as \
            district_event_map_file:

            district_event_map = json.load(district_event_map_file)

        # intermediate csv files are temporary files
        with open(options['census'][0], 'r') as census_file, \
        tempfile.NamedTemporaryFile(mode='w', delete=False,
            suffix='.csv') as user_csv_file, \
        tempfile.NamedTemporaryFile(mode='w', delete=False,
            suffix='.csv') as userdata_csv_file, \
        tempfile.NamedTemporaryFile(mode='w', delete=False,
            suffix='.csv') as acl_csv_file:

            print("Begin processing %s" % census_file.name)
            self.debug("metadata: %s" % metadata)

            census = csv.reader(census_file, delimiter=self.DELIMITER)
            user_writer = csv.writer(user_csv_file, delimiter=self.DELIMITER)
            userdata_writer = csv.writer(userdata_csv_file,
                delimiter=self.DELIMITER)
            acl_writer = csv.writer(acl_csv_file, delimiter=self.DELIMITER)

            print("Writing csvs into [%s %s %s]" % (user_csv_file.name,
                userdata_csv_file.name, acl_csv_file.name))

            # the first row is the header
            header = census.__next__()

            if len(header) != len(set(header)):
                raise ValueError('Header contains duplicate columns')

            # obtain the position of the field from the header
            # to allow lookups when processing rows
            indices = {k: v for v, k in enumerate(header)}

            # start creating users from the first available id
            last_id = User.objects.aggregate(Max('id'))["id__max"]
            if last_id is None:
                last_id = -1
            row = 1

            # process census line by line
            for census_row in census:
                self.debug("processing census row %s =====================\n%s"
                    % (row, census_row))

                if len(census_row) != len(header):
                    raise ValueError('Wrong number of fields, row %d' % row)

                event_id = district_event_map[
                    census_row[indices["DISTRICTE"]]
                ]

                user_values = [
                    last_id + row,
                    hashlib.sha256(
                        census_row[indices["PASSWORD"]].
                        encode("utf-8")).hexdigest(),
                    self.NULL,
                    self.FALSE,
                    "%s_%s" % (census_row[indices["DNI"]],
                        census_row[indices["CODI_POSTAL"]]),
                    census_row[indices["NOM"]],
                    census_row[indices["COGNOM_1"]],
                    "",
                    self.FALSE,
                    self.TRUE,
                    now_date
                ]

                userdata_values = [
                    json.dumps(
                        dict(
                            {m: census_row[indices[m]]
                            for m in metadata},
                            **{"fullname": "%s %s %s" % (
                                census_row[indices["NOM"]],
                                census_row[indices["COGNOM_1"]],
                                census_row[indices["COGNOM_2"]])}
                            )
                    ),
                    self.ACTIVE_STATUS,
                    event_id,
                    last_id + row
                ]

                acl_values = [
                    self.VOTE_PERMISSION,
                    last_id + row,
                    event_id,
                    self.AUTHEVENT_TYPE,
                    now_date
                ]

                self.debug("user %s" % user_values)
                self.debug("userdata %s" % userdata_values)
                self.debug("useracl %s" % acl_values)

                user_writer.writerow(user_values)
                userdata_writer.writerow(userdata_values)
                acl_writer.writerow(acl_values)

                # next census row
                row = row + 1

        end_csv = timer()
        print("Finished csv generation")

        # When copying to postgresql below we use psycopg.copy_expert rather
        # than psycopg.copy_from so that we can specify csv mode for the postgresql
        # COPY command.
        # Otherwise there are problems parsing the json generated
        # by the csv writer.

        print("Begin COPY USER")
        start_copy = timer()

        # We must reopen the temporary csv files created above. If we
        # try to use 'w+b' mode that supports writing and reading without
        # closing we run into trouble with the csv writer as described in
        # https://goo.gl/uJms1G
        # We therefore use mode='w' and write, close, read
        with open(user_csv_file.name, 'r') as user_csv_file:
            curs = connection.cursor()
            curs.copy_expert(
                "COPY %s FROM STDIN WITH CSV DELIMITER '%s' NULL '%s'"
                % (self.USER_TABLE, self.DELIMITER, self.NULL), user_csv_file
            )

        with open(userdata_csv_file.name, 'r') as userdata_csv_file, \
        open(acl_csv_file.name, 'r') as acl_csv_file:
            curs = connection.cursor()

            print("Begin COPY USERDATA")
            curs.copy_expert("COPY %s %s FROM STDIN WITH CSV DELIMITER '%s'"
                % (self.USERDATA_TABLE, self.USERDATA_COPY_COLUMNS,
                self.DELIMITER), userdata_csv_file)

            print("Begin COPY ACL")

            curs.copy_expert("COPY %s %s FROM STDIN WITH CSV DELIMITER '%s'"
                % (self.ACL_TABLE, self.ACL_COPY_COLUMNS, self.DELIMITER),
                acl_csv_file)

        end_copy = timer()

        print("Finished (%.3f s) (%.3f s)" % ((end_csv - start_csv),
            (end_copy - start_csv)))

    def debug(self, message):
        if self.verbose:
            print(message)