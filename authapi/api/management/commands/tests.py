# This file is part of authapi.
# Copyright (C) 2014-2016  Agora Voting SL <agora@agoravoting.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

from django.test import TestCase
from django.test.utils import override_settings
from django.conf import settings
from django.contrib.auth.models import User
from django.core.management import call_command

import tempfile
import json

from api.models import ACL, AuthEvent, UserData
from api import test_data

def flush_db_load_fixture(ffile="initial.json"):
    from django.core import management
    management.call_command("flush", verbosity=0, interactive=False)
    management.call_command("loaddata", ffile, verbosity=0)

# implements a functional and a load test of the bcn import
class TestBcnImport(TestCase):
    LOAD_SIZE = 10000

    def setUpTestData():
        flush_db_load_fixture()

    # functional test
    def test_import(self):
        # create some extra AuthEvent's to test district to event mapping
        ae = AuthEvent(auth_method=test_data.auth_event4['auth_method'],
            auth_method_config=test_data.authmethod_config_email_default)
        ae.save()
        ae = AuthEvent(auth_method=test_data.auth_event4['auth_method'],
            auth_method_config=test_data.authmethod_config_email_default)
        ae.save()

        # 3 census entries
        census = '''NOM;COGNOM_1;COGNOM_2;ADRECA;CODI_POSTAL;DATA_NAIXEMENT;DNI;DISTRICTE;BARRI;CODI_CARRER;NUMERO_CARRER;NUM_ALEATORI_DISTRICTE;NUM_ALEATORI_BARRI;BLOQUEIG;PASSWORD
EJEMPLO_N;EJEMPLO_C1;EJEMPLO_C2;C AÇORES,    5 P01 1;08027;19780702;12345678X;D1;61;029807;0005;1935;5408;S;password
EJEMPLO_N;EJEMPLO_C1;EJEMPLO_C2;C AÇORES,    5 P01 1;08027;19780702;22345678X;D2;61;029807;0005;1935;5408;S;password
EJEMPLO_N;EJEMPLO_C1;EJEMPLO_C2;C AÇORES,    5 P01 1;08027;19780702;32345678X;D3;61;029807;0005;1935;5408;S;password
'''
        district_event_map = '''{"D1":1, "D2": 2, "D3": 3}'''
        # convenience for the tests below
        district_event_map_dict = json.loads(district_event_map)
        # we need to capture these for the tests below
        metadata = ["NOM", "COGNOM_1", "COGNOM_2", "DNI", "CODI_POSTAL", "DISTRICTE"]

        self.go(census, district_event_map, metadata, True)

        # skip data that was already in the fixture: id > 1
        users = User.objects.filter(id__gt = 1)
        userdata = UserData.objects.filter(id__gt = 1)
        acls = ACL.objects.filter(id__gt = 1)

        # test asssertions

        self.assertEqual(len(users), 3)
        self.assertEqual(len(userdata), 3)
        self.assertEqual(len(acls), 3)

        for user in users:
            meta = user.userdata.metadata
            # the username was properly constructed
            self.assertEqual(user.username, "%s_%s" %
                (meta["DNI"], meta["CODI_POSTAL"])
            )

            # the fullname meta field was properly constructed
            self.assertEqual(meta["fullname"], "%s %s %s" %
                (meta["NOM"], meta["COGNOM_1"], meta["COGNOM_2"])
            )

            # the district to authevent map was correct
            self.assertEqual(district_event_map_dict[
                meta["DISTRICTE"]], user.userdata.event.id)

            # the user has vote permission
            self.assertEqual(user.userdata.has_perms("AuthEvent", "vote",
                user.userdata.event.id), True)

    # load (performance) test
    def test_import_large(self):

        census = "NOM;COGNOM_1;COGNOM_2;ADRECA;CODI_POSTAL;DATA_NAIXEMENT;DNI;DISTRICTE;BARRI;CODI_CARRER;NUMERO_CARRER;NUM_ALEATORI_DISTRICTE;NUM_ALEATORI_BARRI;BLOQUEIG;PASSWORD"
        for i in range(0, self.LOAD_SIZE):
            census += "\nEJEMPLO_N;EJEMPLO_C1;EJEMPLO_C2;C AÇORES,    5 P01 1;08027;19780702;%s2345678X;09;61;029807;0005;1935;5408;S;password" % i

        district_event_map = '''{"09":1}'''
        metadata = ["NOM"]

        self.go(census, district_event_map, metadata)

    # helper
    def go(self, census, district_event_map, metadata, verbose=False):

        with tempfile.NamedTemporaryFile(suffix='.csv') as census_file, \
             tempfile.NamedTemporaryFile(suffix='.csv') as district_event_file:
            print("TestBcnImport: writing mock data to %s" % census_file.name)
            census_file.write(census.encode("utf-8"))
            census_file.flush()

            print("TestBcnImport: writing mock data to %s" % district_event_file.name)
            district_event_file.write(district_event_map.encode("utf-8"))
            district_event_file.flush()

            args = [census_file.name, district_event_file.name]
            if verbose:
                args.append("--verbose")
            opts = {"metadata": metadata}
            call_command('import_bcn_census', *args, **opts)