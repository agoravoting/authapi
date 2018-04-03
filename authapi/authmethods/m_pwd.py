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

import json
import logging
from . import register_method
from utils import genhmac
from django.conf import settings
from django.contrib.auth.models import User
from django.conf.urls import url
from django.db.models import Q

from utils import json_response
from utils import stack_trace_str
from django.contrib.auth.signals import user_logged_in
from authmethods.utils import *


LOGGER = logging.getLogger('authapi')


def testview(request, param):
    data = {'status': 'ok'}
    return json_response(data)


class PWD:
    DESCRIPTION = 'Register using user and password. '
    CONFIG = {}
    PIPELINES = {
        "register-pipeline": [],
        "authenticate-pipeline": [],
        'give_perms': [
            {'object_type': 'UserData', 'perms': ['edit',], 'object_id': 'UserDataId' },
            {'object_type': 'AuthEvent', 'perms': ['vote',], 'object_id': 'AuthEventId' }
        ],
    }
    username_definition = { "name": "username", "type": "text", "required": True, "min": 3, "max": 200, "required_on_authentication": True }
    password_definition = { "name": "password", "type": "password", "required": True, "min": 3, "max": 200, "required_on_authentication": True }

    def check_config(self, config):
        return ''

    def resend_auth_code(self, config):
        return {'status': 'ok'}

    def census(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        validation = req.get('field-validation', 'enabled') == 'enabled'

        msg = ''
        usernames = []
        for r in req.get('census'):
            username = r.get('username')
            password = r.get('password')
            msg += check_field_type(self.username_definition, username)
            msg += check_field_type(self.password_definition, password)
            if validation:
                msg += check_field_type(self.username_definition, username)
                msg += check_field_value(self.username_definition, username)
                msg += check_field_type(self.password_definition, password)
                msg += check_field_value(self.password_definition, password)

            msg += check_fields_in_request(r, ae, 'census', validation=validation)
            if validation:
                msg += exist_user(r, ae)
                if username in usernames:
                    msg += "Username %s repeat in this census." % username
                usernames.append(username)
            else:
                if msg:
                    LOGGER.debug(\
                        "PWD.census warning\n"\
                        "error (but validation disabled) '%r'\n"\
                        "request '%r'\n"\
                        "validation '%r'\n"\
                        "authevent '%r'\n"\
                        "Stack trace: \n%s",\
                        msg, req, validation, ae, stack_trace_str())
                    msg = ''
                    continue
                exist = exist_user(r, ae)
                if exist and not exist.count('None'):
                    continue
                # By default we creates the user as active we don't check
                # the pipeline
                u = create_user(r, ae, True, request.user, user=username, password=password)
                give_perms(u, ae)
        if msg and validation:
            LOGGER.error(\
                "PWD.census error\n"\
                "error '%r'\n"\
                "request '%r'\n"\
                "validation '%r'\n"\
                "authevent '%r'\n"\
                "Stack trace: \n%s",\
                msg, req, validation, ae, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        if validation:
            for r in req.get('census'):
                # By default we creates the user as active we don't check
                # the pipeline
                u = create_user(r, ae, True, request.user, user=username, password=password)
                give_perms(u, ae)
        
        ret = {'status': 'ok'}
        LOGGER.debug(\
            "PWD.census\n"\
            "request '%r'\n"\
            "validation '%r'\n"\
            "authevent '%r'\n"\
            "returns '%r'\n"\
            "Stack trace: \n%s",\
            req, validation, ae, ret, stack_trace_str())
        return ret

    def authenticate_error(self, error, req, ae):
        d = {'status': 'nok'}
        LOGGER.error(\
            "PWD.census error\n"\
            "error '%r'\n"\
            "request '%r'\n"\
            "authevent '%r'\n"\
            "Stack trace: \n%s",\
            error, req, ae, stack_trace_str())
        return d

    def authenticate(self, ae, request, mode="authenticate"):
        d = {'status': 'ok'}
        req = json.loads(request.body.decode('utf-8'))
        username = req.get('username', '')
        pwd = req.get('password', '')

        msg = ""
        msg += check_fields_in_request(req, ae, 'authenticate')
        if msg:
            LOGGER.error(\
                "PWD.authenticate error\n"\
                "error '%r'"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, ae, req, stack_trace_str())
            return self.authenticate_error("invalid-fields-check", req, ae)

        try:
            q = Q(userdata__event=ae, is_active=True)

            if 'username' in req:
                q = q & Q(username=username)
            elif not settings.MAKE_LOGIN_KEY_PRIVATE:
                return self.authenticate_error("no-username-provided", req, ae)

            q = get_required_fields_on_auth(req, ae, q)
            u = User.objects.get(q)
        except:
            return self.authenticate_error("user-not-found", req, ae)

        msg = check_pipeline(request, ae, 'authenticate')
        if msg:
            return self.authenticate_error("invalid-pipeline", req, ae)

        if mode == "authenticate":
            if not u.check_password(pwd):
                return self.authenticate_error("invalid-password", req, ae)

            if (ae.num_successful_logins_allowed > 0 and
                u.userdata.successful_logins.filter(is_active=True).count() >= ae.num_successful_logins_allowed):
                return self.authenticate_error(
                    "invalid_num_successful_logins_allowed", req, ae)

            user_logged_in.send(sender=u.__class__, request=request, user=u)
            u.save()

            d['username'] = u.username
            d['auth-token'] = genhmac(settings.SHARED_SECRET, u.username)

            # add redirection
            auth_action = ae.auth_method_config['config']['authentication-action']
            if auth_action['mode'] == 'go-to-url':
                data['redirect-to-url'] = auth_action['mode-config']['url']

        LOGGER.debug(\
            "PWD.authenticate success\n"\
            "returns '%r'\n"\
            "authevent '%r'\n"\
            "request '%r'\n"\
            "Stack trace: \n%s",\
            d, ae, req, stack_trace_str())
        return d

    def public_census_query(self, ae, request):
        # whatever
        return self.authenticate(ae, request, "census-query")

    views = [
        url(r'^test/(\w+)$', testview),
    ]


register_method('user-and-password', PWD)
