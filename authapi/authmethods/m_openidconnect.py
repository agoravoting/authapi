# This file is part of authapi.
# Copyright (C) 2018  Agora Voting SL <agora@agoravoting.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

from . import register_method
from utils import genhmac, constant_time_compare, json_response, stack_trace_str
from authmethods.utils import *

from django.conf import settings
from django.contrib.auth.models import User
from django.conf.urls import url
from django.db.models import Q
from django.contrib.auth.signals import user_logged_in

import requests
import json
import logging

from oic.oic import Client
from oic.oic.message import (
    ProviderConfigurationResponse,
    RegistrationResponse,
    AuthorizationResponse
)
from oic.utils.keyio import KeyBundle, KeyJar
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.time_util import utc_time_sans_frac

LOGGER = logging.getLogger('authapi')


def testview(request, param):
    data = {'status': 'ok'}
    return json_response(data)


class OpenIdConnect(object):
    '''
    Allows authentication with OpenID Connect 1.0

    Reference standard:
    https://openid.net/specs/openid-connect-core-1_0.html
    '''

    DESCRIPTION = 'Authenticate using OpenID Connect 1.0'
    CONFIG = {}
    PIPELINES = {
        "register-pipeline": [],
        "authenticate-pipeline": [],
        'give_perms': [
            {'object_type': 'UserData', 'perms': ['edit',], 'object_id': 'UserDataId' },
            {'object_type': 'AuthEvent', 'perms': ['vote',], 'object_id': 'AuthEventId' }
        ],
    }
    USED_TYPE_FIELDS = ['sub']
    sub_definition = {
      "name": "sub",
      "type": "text",
      "required": True,
      "min": 1,
      "max": 255,
      "required_on_authentication": True
    }

    PROVIDERS = dict()

    def __init__(self):
        for conf in settings.OPENID_CONNECT_PROVIDERS_CONF:
            keyjar = KeyJar()
            keyjar.add(
                conf['public_info']['issuer'],
                conf['public_info']['jwks_uri']
            )

            client = Client(
                client_authn_method=CLIENT_AUTHN_METHOD,
                keyjar=keyjar
            )

            client.provider_info = ProviderConfigurationResponse(
                version='1.0',
                **conf['public_info']
            )
            registration_data = dict(
              client_id=conf['public_info']['client_id'],
              **conf["private_config"]
            )
            registration_response = RegistrationResponse().from_dict(registration_data)
            client.store_registration_info(registration_response)

            self.PROVIDERS[conf['public_info']['id']] = dict(
                conf=conf,
                client=client
            )

    def check_config(self, config):
        return ''

    def resend_auth_code(self, config):
        return {'status': 'ok'}

    def census(self, ae, request):
        return {'status': 'ok'}

    def authenticate_error(self, error, req, ae, message=""):
        d = {'status': 'nok'}
        LOGGER.error(\
            "OpenIdConnect.authenticate error\n"\
            "error '%r'\n"\
            "message '%r'\n"\
            "request '%r'\n"\
            "authevent '%r'\n"\
            "Stack trace: \n%s",\
            error, message, req, ae, stack_trace_str())
        return d

    def authenticate(self, auth_event, request, mode='authenticate'):
        ret_data = {'status': 'ok'}
        req = json.loads(request.body.decode('utf-8'))
        id_token = req.get('id_token', '')
        provider_id = req.get('provider', '')
        nonce = req.get('nonce', '')

        if provider_id not in self.PROVIDERS:
            return self.authenticate_error("invalid-provider", req, auth_event)

        provider = self.PROVIDERS[provider_id]
        # parses and verifies/validates the id token
        id_token_obj = provider['client'].parse_response(
            AuthorizationResponse,
            info=id_token,
            sformat="jwt",
            keyjar=provider['client'].keyjar,
            scope="openid"
        )
        if not id_token_obj:
            return self.authenticate_error("invalid-id-token", req, auth_event,
                message="id_token_obj is empty")

        # verify nonce securely
        id_token_dict = id_token_obj.to_dict()
        if not constant_time_compare(id_token_dict['nonce'], nonce):
            return self.authenticate_error("invalid-nonce", req, auth_event,
                message="'%r' != '%r'" % (id_token_dict['nonce'], nonce))

        # verify client_id
        if not constant_time_compare(id_token_dict['aud'], provider['conf']['public_info']['client_id']):
            return self.authenticate_error("invalid-aud", req, auth_event,
                message="'%r' != '%r'" % (id_token_dict['aud'], provider['conf']['public_info']['client_id']))

        # verify expiration
        current_timestamp = utc_time_sans_frac()
        if id_token_dict['exp'] < current_timestamp:
            return self.authenticate_error("invalid-exp", req, auth_event,
                message="'%r' != '%r'" % (id_token_dict['exp'], current_timestamp))

        # get user_id and get/create user
        user_id = id_token_dict['sub']
        try:
            user = User.objects.get(
                userdata__event=auth_event,
                userdata__metadata__contains={"sub": user_id}
            )
        except:
            user = create_user(
                req=dict(sub=user_id),
                ae=auth_event,
                active=True,
                creator=request.user)
            give_perms(user, auth_event)

        msg = check_pipeline(request, auth_event, 'authenticate')
        if msg:
            return self.authenticate_error("invalid-pipeline", req, auth_event,
                message=msg)

        if mode == "authenticate":
            if not user.is_active:
                return self.authenticate_error("user-inactive", req, auth_event)

            if not verify_num_successful_logins(auth_event, 'OpenIdConnect', user, req):
                return self.authenticate_error(
                    "invalid_num_successful_logins_allowed", req, auth_event
                )

            return return_auth_data(
                auth_event, 
                'OpenIdConnect', 
                req, 
                request, 
                user,
                extra_debug="id_token_dict '%r'\n" % id_token_dict
            )

        LOGGER.debug(\
            "OpenIdConnect.authenticate success\n"\
            "returns '%r'\n"\
            "authevent '%r'\n"\
            "id_token_dict '%r'\n"\
            "request '%r'\n"\
            "Stack trace: \n%s",\
            ret_data, auth_event, id_token_dict, req, stack_trace_str())
        return ret_data

    def public_census_query(self, ae, request):
        # whatever
        return self.authenticate(ae, request, "census-query")

    views = [
        url(r'^test/(\w+)$', testview),
    ]


register_method('openid-connect', OpenIdConnect)
