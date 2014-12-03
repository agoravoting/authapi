import json
from . import register_method
from utils import genhmac
from django.conf import settings
from django.contrib.auth.models import User
from django.conf.urls import patterns, url
from django.http import HttpResponse


def testview(request, param):
    data = {'status': 'ok'}
    jsondata = json.dumps(data)
    return HttpResponse(jsondata, content_type='application/json')


class PWD:
    DESCRIPTION = 'Register using user and password. '
    TPL_CONFIG = {}

    def login_error(self):
        d = {'status': 'nok'}
        return d
    def login(self, data):
        d = {'status': 'ok'}
        msg = data['username']
        pwd = data['password']

        try:
            u = User.objects.get(username=msg)
        except:
            return self.login_error()

        if not u.check_password(pwd):
            return self.login_error()

        d['auth-token'] = genhmac(settings.SHARED_SECRET, msg)
        return d

    views = patterns('',
        url(r'^test/(\w+)$', testview),
    )


register_method('user-and-password', PWD)