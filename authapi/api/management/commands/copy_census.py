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

import os
import json
import csv
import tempfile
from datetime import datetime
import hashlib
import platform
import tarfile
import shutil

from api.models import AuthEvent, ACL, User, UserData
from timeit import default_timer as timer

#
# Census import/export command.
#
# The 'copy_census to' command creates an archive with
#
# 1) AuthEvent data
# 2) User data
# 3) UserData data
# 4) ACL data
#
# corresponding to the specified events passed with the --eventids argument.
# Data is exported with posgresql COPY command to files generated in an
# intermediate directory. This directory is deleted at the end of the export.
#
# The 'copy_census from' command imports data from an archive. The following
#
# 1) AuthEvent data [optional, see below]
# 2) User data
# 3) UserData data
# 4) ACL data
#
# is imported with posgresql COPY command. Existing data is first deleted:
#
# 1) User data for corresponding events
# 2) UserData data for corresponding events
# 3) ACL data for corresponding events
#
# If required AuthEvent data is already present at the target database it is
# not copied. If some of this data is present but not all, an error is reported.
# An intermediate directory is used to extract files from the archive. This
# directory is deleted at the end of the import.
#
# Assumptions
#
# 1) The database schema exists at the target
# 2) All or none of the required AuthEvent data is present in the target
# 3) There are no additional dependencies at the target
#    db (for example authmethods.Code)
#
# If these are not met the script will bomb with an error.
#
# CLI usage described by
#
# manage.py copy_census -h
#
#
# Testing
#
# manage.py test api.management.commands.tests.TestCopyCensus
# --settings=authapi.test_settings --nocapture
#
#
class Command(BaseCommand):
    help = 'imports and exports census data'

    EVENT_FILE = "events"
    USER_FILE = "users"
    USERDATA_FILE = "userdata"
    ACL_FILE = "acls"
    MANIFEST_FILE = "manifest"

    EVENT_TABLE = "api_authevent"
    USER_TABLE = "auth_user"
    USERDATA_TABLE = "api_userdata"
    ACL_TABLE = "api_acl"

    # we set this explicitly in case the setting differs across installations
    DATESTYLE = "ISO, MDY"

    # the --verbose flag
    verbose = False

    def add_arguments(self, parser):
        parser.add_argument('action', nargs=1, type=str, help=
            'Should be one of "to" or "from", for export or import')
        parser.add_argument('file', nargs=1, type=str, help=
            'The archive file to copy FROM or TO')
        parser.add_argument('--eventids', nargs='*', default=[], type=list,
            help= 'List of event ids to export from, ignored when importing')
        parser.add_argument('--verbose', nargs='?', const=True, help=
            'If present shows extra debug info')

    # Import data from the given file_name.
    # If the required events are not present in the database they
    # will be loaded from the import file.
    # Existing user, userdata and acl data belonging to the events
    # present in the import file will be deleted prior to import. Existing
    # events are never deleted.
    def from_(self, file_name):
        # Create a temporary directory to extract the import file
        directory = tempfile.mkdtemp(suffix=".census_copy")
        self.debug("Directory: %s" % directory)

        print("Opening import file: %s " % file_name)
        tar = tarfile.open(file_name)
        tar.extractall(path=directory)
        tar.close()

        cursor = connection.cursor()

        # set the datestyle to match our generated dates
        cursor.execute("SET DateStyle='%s'" % self.DATESTYLE)

        # Obtain the event ids from the manifest
        with open(os.path.join(directory, self.MANIFEST_FILE), "r", \
            encoding='utf-8') as manifest_file:

            manifest = json.load(manifest_file)

        event_ids = manifest['events']

        # Sanity check, before injecting this value into queries
        if all(isinstance(item, int) for item in event_ids) != True:
            raise ValueError("Unexpected event_ids type")

        # The event_ids field must be present when importing
        if len(event_ids) == 0:
            raise ValueError("Unexpected number of events in manifest")

        self.debug("Importing with event ids: %s " % event_ids)

        with open(os.path.join(directory, self.EVENT_FILE), "r", \
            encoding='utf-8') as manifest_file, \
        open(os.path.join(directory, self.EVENT_FILE), "r", \
            encoding='utf-8') as event_file, \
        open(os.path.join(directory, self.USER_FILE), "r", \
            encoding='utf-8') as user_file, \
        open(os.path.join(directory, self.USERDATA_FILE), "r", \
            encoding='utf-8') as userdata_file, \
        open(os.path.join(directory, self.ACL_FILE), "r", \
            encoding='utf-8') as acl_file:

            # Importing events follows this logic:
            # if none of the events are present at the target database we import them
            # if all are present we do not import them
            # otherwise we raise an error
            count = AuthEvent.objects.filter(id__in=event_ids).count()
            if count == 0:
                print("Begin COPY events")
                cursor.copy_expert("COPY %s FROM STDIN ENCODING 'UTF8'"
                    % self.EVENT_TABLE, event_file)
            elif count != len(event_ids):
                raise ValueError("Unexpected number of events present in db")

            # We use this in raw deletion queries
            event_ids_string = self.event_ids_string(event_ids)

            # We must delete UserData table last as it is used in joins
            # when deleting in the above 2 tables. This does not
            # run into problems with foreign keys, since checks
            # are DEFERRED until transaction commit
            query = self.user_delete_query(event_ids_string)
            self.debug("User delete query: %s" % query)
            cursor.execute(query)

            query = self.acl_delete_query(event_ids_string)
            self.debug("ACL delete query: %s" % query)
            cursor.execute(query)

            query = self.userdata_delete_query(event_ids_string)
            self.debug("UserData delete query: %s" % query)
            cursor.execute(query)

            print("Begin COPY users")
            cursor.copy_expert("COPY %s FROM STDIN ENCODING 'UTF8'"
                    % self.USER_TABLE, user_file)

            print("Begin COPY userdata")
            cursor.copy_expert("COPY %s FROM STDIN ENCODING 'UTF8'"
                    % self.USERDATA_TABLE, userdata_file)

            print("Begin COPY acls")
            cursor.copy_expert("COPY %s FROM STDIN ENCODING 'UTF8'"
                    % self.ACL_TABLE, acl_file)

            self.debug("Removing directory: %s" % directory)
            shutil.rmtree(directory)

    # Export census data into the given file_name, for the specified
    # event ids.
    # Export data includes events, users, userdata and acls.
    # If event_ids is an empty array, data for all events is exported.
    def to(self, file_name, event_ids):
        # Create a temporary directory as a workspace before archiving
        directory = tempfile.mkdtemp(suffix=".census_copy")
        self.debug("Directory: %s" % directory)

        print("Exporting with event ids: %s " % event_ids)

        with open(os.path.join(directory, self.EVENT_FILE), "w", \
            encoding='utf-8') as events_file, \
        open(os.path.join(directory, self.USER_FILE), "w", \
            encoding='utf-8') as users_file, \
        open(os.path.join(directory, self.USERDATA_FILE), "w", \
            encoding='utf-8') as userdata_file, \
        open(os.path.join(directory, self.ACL_FILE), "w", \
            encoding='utf-8') as acls_file, \
        open(os.path.join(directory, self.MANIFEST_FILE), "w", \
            encoding='utf-8') as manifest_file:

            # Sanity check, before injecting this value into queries
            if all(isinstance(item, int) for item in event_ids) != True:
                raise ValueError("Unexpected event_ids type")

            # We must set the list of exported ids in the manifest. This
            # may or may not match the argument passed in.
            if len(event_ids) == 0:
                event_ids = AuthEvent.objects.values_list('id', flat=True)
            else:
                event_ids = AuthEvent.objects.filter(id__in = event_ids) \
                    .values_list('id', flat=True)

            if len(event_ids) == 0:
                raise ValueError("No events found in database")

            # We use this when creating raw select queries.
            event_ids_string = self.event_ids_string(event_ids)

            cursor = connection.cursor()

            # set the datestyle to match our generated dates
            cursor.execute("SET DateStyle='%s'" % self.DATESTYLE)

            print("Begin COPY events")
            query = self.event_query(event_ids_string)
            self.debug("event query: %s" % query)
            cursor.copy_expert("COPY (%s) TO STDIN ENCODING 'UTF8'"
                % query, events_file)

            print("Begin COPY users")
            query = self.user_query(event_ids_string)
            self.debug("user query: %s" % query)
            cursor.copy_expert("COPY (%s) TO STDIN ENCODING 'UTF8'"
                % query, users_file)

            print("Begin COPY userdata")
            query = self.userdata_query(event_ids_string)
            self.debug("userdata query: %s" % query)
            cursor.copy_expert("COPY (%s) TO STDIN ENCODING 'UTF8'"
                % query, userdata_file)

            print("Begin COPY acls")
            query = self.acl_query(event_ids_string)
            self.debug("acl query: %s" % query)
            cursor.copy_expert("COPY (%s) TO STDIN ENCODING 'UTF8'"
                % query, acls_file)


            # The events field is necessary for importing. The other two
            # fields are informative.
            manifest = {
                "events": list(event_ids),
                "source": platform.uname(),
                "date": datetime.now().strftime("%m-%d-%Y %H:%M:%S")
            }
            manifest_file.write(json.dumps(manifest))

        print("Saving export to file: %s " % file_name)
        tar = tarfile.open(file_name, "w")
        tar.add(directory, arcname='.')
        tar.close()

        self.debug("Removing directory: %s" % directory)
        shutil.rmtree(directory)

    def handle(self, *args, **options):
        if options['verbose'] is not None:
            self.verbose = True

        # the file to export to or import from
        file_name = options["file"][0]

        # the event ids that we are exporting, when importing this is ignored
        event_ids = options["eventids"]

        start = timer()

        if options['action'][0] == "from":
            self.from_(file_name)
        elif options['action'][0] == "to":
            self.to(file_name, event_ids)
        else:
            raise ValueError("Unexpected command %s " % options['action'][0])

        end = timer()

        print("Finished copy_census %s (%.3f s)" % (options['action'][0],
            (end - start)))

    # Determines which events, given the passed event ids, are exported
    def event_query(self, event_ids_string):
        query = "SELECT * FROM %s" % self.EVENT_TABLE
        if event_ids_string != "":
            query += " WHERE ID IN (%s)" % event_ids_string

        return query

    # Determines which users, given the passed event ids, are exported
    def user_query(self, event_ids_string):
        query = "SELECT A.* FROM %s A JOIN %s ON A.id = user_id" % (
            self.USER_TABLE, self.USERDATA_TABLE)
        if event_ids_string != "":
            query += " WHERE EVENT_ID IN (%s)" % event_ids_string

        return query

    # Determines which userdata, given the passed event ids, are exported
    def userdata_query(self, event_ids_string):
        query = "SELECT * FROM %s" % self.USERDATA_TABLE
        if event_ids_string != "":
            query += " WHERE EVENT_ID IN (%s)" % event_ids_string

        return query

    # Determines which acls, given the passed event ids, are exported
    def acl_query(self, event_ids_string):
        query = "SELECT A.* FROM %s A JOIN %s ON A.user_id = %s.id" % (
            self.ACL_TABLE, self.USERDATA_TABLE,
            self.USERDATA_TABLE)
        if event_ids_string != "":
            query += " WHERE EVENT_ID IN (%s)" % event_ids_string

        return query

    # Determines which users, given the passed event ids, are deleted
    def user_delete_query(self, event_ids_string):
        query = "DELETE FROM %s USING %s WHERE %s.id = %s.user_id" \
            " and EVENT_ID in (%s)" % (self.USER_TABLE, self.USERDATA_TABLE,
            self.USER_TABLE, self.USERDATA_TABLE, event_ids_string)

        return query

    # Determines which userdata, given the passed event ids, are deleted
    def userdata_delete_query(self, event_ids_string):
        query = "DELETE FROM %s WHERE EVENT_ID in (%s)" % (
            self.USERDATA_TABLE, event_ids_string)

        return query

    # Determines which acls, given the passed event ids, are deleted
    def acl_delete_query(self, event_ids_string):
        query = "DELETE FROM %s USING %s WHERE %s.user_id = %s.id" \
            " and EVENT_ID in (%s)" % (self.ACL_TABLE, self.USERDATA_TABLE,
            self.ACL_TABLE, self.USERDATA_TABLE, event_ids_string)

        return query

    # Converts a list of ids into a string suitable for query injection
    def event_ids_string(self, event_ids):
        if len(event_ids) > 0:
            return (",".join(str(x) for x in event_ids))
        else:
            return ""

    def debug(self, message):
        if self.verbose:
            print(message)