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
from django.db import connection
from django.core.management import call_command

import tempfile
import json
import os

from api.models import ACL, AuthEvent, UserData
from authmethods.models import Code
from api import test_data

def flush_db_load_fixture(ffile="initial.json"):
    from django.core import management
    management.call_command("flush", verbosity=0, interactive=False)
    management.call_command("loaddata", ffile, verbosity=0)

def flush_db():
    from django.core import management
    management.call_command("flush", verbosity=0, interactive=False)

def load_data_large(size):
    census = "NOM;COGNOM_1;COGNOM_2;ADRECA;CODI_POSTAL;DATA_NAIXEMENT;DNI;DISTRICTE;BARRI;CODI_CARRER;NUMERO_CARRER;NUM_ALEATORI_DISTRICTE;NUM_ALEATORI_BARRI;BLOQUEIG;PASSWORD"
    for i in range(0, size):
        census += "\nEJEMPLO_N;EJEMPLO_C1;EJEMPLO_C2;C AÇORES,    5 P01 1;08027;19780702;%s2345678X;09;61;029807;0005;1935;5408;S;password" % i

    district_event_map = '''{"09":1}'''
    metadata = ["NOM"]

    bcn_import(census, district_event_map, metadata)

def bcn_import(census, district_event_map, metadata, verbose=False):

    with tempfile.NamedTemporaryFile(suffix='.csv') as census_file, \
    tempfile.NamedTemporaryFile(suffix='.csv') as district_event_file:

        print("bcn_import: writing mock data to %s" % census_file.name)
        census_file.write(census.encode("utf-8"))
        census_file.flush()

        print("bcn_import: writing mock data to %s" % district_event_file.name)
        district_event_file.write(district_event_map.encode("utf-8"))
        district_event_file.flush()

        args = [census_file.name, district_event_file.name]
        if verbose:
            args.append("--verbose")
        opts = {"metadata": metadata}
        call_command('import_bcn_census', *args, **opts)

# implements a functional test of the census_copy command
class TestCopyCensus(TestCase):
    LOAD_SIZE = 100000

    def setUp(self):
        flush_db()
    # manage.py test api.management.commands.tests.TestCensusCopy --settings=authapi.test_settings --nocapture

    def test_copy(self):

        ae = AuthEvent(auth_method=test_data.auth_event4['auth_method'],
            auth_method_config=test_data.authmethod_config_email_default)
        ae.save()

        ae2 = AuthEvent(auth_method=test_data.auth_event4['auth_method'],
            auth_method_config=test_data.authmethod_config_email_default)
        ae2.save()

        ae3 = AuthEvent(auth_method=test_data.auth_event4['auth_method'],
            auth_method_config=test_data.authmethod_config_email_default)
        ae3.save()

        u = User(username="1", email="2")
        u.set_password("p")
        u.save()
        u.userdata.event = ae
        u.userdata.save()

        u2 = User(username="2", email="2")
        u2.set_password("p")
        u2.save()
        u2.userdata.event = ae2
        u2.userdata.save()

        u3 = User(username="3", email="2")
        u3.set_password("p")
        u3.save()
        u3.userdata.event = ae3
        u3.userdata.save()

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='vote', object_id=ae.id)
        acl.save()

        acl2 = ACL(user=u2.userdata, object_type='AuthEvent', perm='vote', object_id=ae2.id)
        acl2.save()

        acl3 = ACL(user=u3.userdata, object_type='AuthEvent', perm='vote', object_id=ae3.id)
        acl3.save()

        #
        # Test 1: export import with all events (events = [])
        #

        events = AuthEvent.objects.all()
        users = User.objects.all()
        userdata = UserData.objects.all()
        acls = ACL.objects.all()

        self.assertEqual(len(events), 3)
        self.assertEqual(len(users), 3)
        self.assertEqual(len(userdata), 3)
        self.assertEqual(len(acls), 3)

        event_ids = []
        action = "to"
        file_name = os.path.join(tempfile.gettempdir(), "/tmp/sample.tar")

        args = [action, file_name, "--verbose"]
        opts = {"eventids": event_ids}
        call_command('copy_census', *args, **opts)

        action = "from"
        args = [action, file_name, "--verbose"]
        call_command('copy_census', *args, **opts)

        events = AuthEvent.objects.all()
        users = User.objects.all()
        userdata = UserData.objects.all()
        acls = ACL.objects.all()

        self.assertEqual(len(events), 3)
        self.assertEqual(len(users), 3)
        self.assertEqual(len(userdata), 3)
        self.assertEqual(len(acls), 3)

        for i in range(0, 3):
            self.assertEqual(users[i].username, str(i + 1))
            self.assertEqual(userdata[i].event_id, i + 1)
            self.assertEqual(users[i].userdata.has_perms(
                "AuthEvent", "vote", users[i].userdata.event.id), True)

        #
        # Test 2: export import with events = [2, 3]
        #

        action = "to"
        args = [action, file_name, "--verbose"]
        event_ids = [2, 3]
        opts = {"eventids": event_ids}
        call_command('copy_census', *args, **opts)

        action = "from"
        args = [action, file_name, "--verbose"]
        call_command('copy_census', *args, **opts)

        events = AuthEvent.objects.all()
        users = User.objects.all()
        userdata = UserData.objects.all()
        acls = ACL.objects.all()

        self.assertEqual(len(events), 3)
        self.assertEqual(len(users), 3)
        self.assertEqual(len(userdata), 3)
        self.assertEqual(len(acls), 3)

        #
        # Test 2: export import with events = [2, 3, 500]
        #

        action = "to"
        args = [action, file_name, "--verbose"]
        event_ids = [2, 3, 500]
        opts = {"eventids": event_ids}
        call_command('copy_census', *args, **opts)

        action = "from"
        args = [action, file_name, "--verbose"]
        call_command('copy_census', *args, **opts)

        events = AuthEvent.objects.all()
        users = User.objects.all()
        userdata = UserData.objects.all()
        acls = ACL.objects.all()

        self.assertEqual(len(events), 3)
        self.assertEqual(len(users), 3)
        self.assertEqual(len(userdata), 3)
        self.assertEqual(len(acls), 3)

        #
        # Test 4: export import with events = [2, 3], delete db
        #

        action = "to"
        args = [action, file_name, "--verbose"]
        event_ids = [2, 3]
        opts = {"eventids": event_ids}
        call_command('copy_census', *args, **opts)

        AuthEvent.objects.all().delete()
        User.objects.all().delete()

        action = "from"
        args = [action, file_name, "--verbose"]
        call_command('copy_census', *args, **opts)

        events = AuthEvent.objects.all()
        users = User.objects.all()
        userdata = UserData.objects.all()
        acls = ACL.objects.all()

        self.assertEqual(len(events), 2)
        self.assertEqual(len(users), 2)
        self.assertEqual(len(userdata), 2)
        self.assertEqual(len(acls), 2)

        for i in range(0, 2):
            self.assertEqual(users[i].username, str(i + 2))
            self.assertEqual(userdata[i].event_id, i + 2)
            self.assertEqual(users[i].userdata.has_perms(
                "AuthEvent", "vote", users[i].userdata.event.id), True)

    def test_copy_large(self):
        ae = AuthEvent(auth_method=test_data.auth_event4['auth_method'],
            auth_method_config=test_data.authmethod_config_email_default)
        ae.save()

        ae2 = AuthEvent(auth_method=test_data.auth_event4['auth_method'],
            auth_method_config=test_data.authmethod_config_email_default)
        ae2.save()

        ae3 = AuthEvent(auth_method=test_data.auth_event4['auth_method'],
            auth_method_config=test_data.authmethod_config_email_default)
        ae3.save()

        print("Generating and loading mock data")

        load_data_large(self.LOAD_SIZE)

        event_ids = []
        action = "to"
        file_name = os.path.join(tempfile.gettempdir(), "/tmp/sample.tar")

        args = [action, file_name, "--verbose"]
        opts = {"eventids": event_ids}

        print("Begin copy to")
        call_command('copy_census', *args, **opts)

        print("Deleting existing data")

        AuthEvent.objects.all().delete()
        User.objects.all().delete()

        action = "from"
        args = [action, file_name, "--verbose"]

        print("Begin copy from")

        call_command('copy_census', *args, **opts)

        events = AuthEvent.objects.all().count()
        users = User.objects.all().count()
        userdata = UserData.objects.all().count()
        acls = ACL.objects.all().count()

        self.assertEqual(events, 3)
        self.assertEqual(users, self.LOAD_SIZE)
        self.assertEqual(userdata, self.LOAD_SIZE)
        self.assertEqual(acls, self.LOAD_SIZE)

# implements a functional and a load test of the bcn import
class TestBcnImport(TestCase):
    LOAD_SIZE = 10000

    def setUp(self):
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
        metadata = ["NOM", "COGNOM_1", "COGNOM_2", "DNI", "CODI_POSTAL", "DISTRICTE", "ADRECA"]

        bcn_import(census, district_event_map, metadata, True)

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
        load_data_large(self.LOAD_SIZE)