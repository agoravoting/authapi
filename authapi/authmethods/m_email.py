import json
from django.conf import settings
from django.conf.urls import patterns, url
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.http import HttpResponse
from string import ascii_letters, digits
from utils import genhmac, constant_time_compare

from . import register_method
from authmethods.utils import random_code
from api.models import AuthEvent, ACL


def register(request, method):
    req = json.loads(request.body.decode('utf-8'))
    mail_to = req.get('email')
    user = req.get('user')
    pwd = req.get('password')

    try:
        u = User(username=user)
        u.set_password(pwd)
        u.save()
    except:
        data = {'msg': 'user already exist'}
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, status=400, content_type='application/json')

    # check method event
    eo = AuthEvent.objects.get(pk=method)

    conf = json.loads(eo.auth_method_config)
    subject = conf.get('subject')
    mail_from = conf.get('mail_from')

    code = random_code(64, ascii_letters+digits)
    valid_link = request.build_absolute_uri(
            '/authmethod/email/validate/%d/%s' % (u.pk,  code))
    msg = conf.get('msg') + valid_link

    u.userdata.event = eo
    u.userdata.metadata = json.dumps({
            'email': mail_to,
            'code': code,
            'email_verified': False
    })
    u.userdata.save()

    send_mail(subject, msg, mail_from, (mail_to,), fail_silently=False)
    data = {'status': 'ok'}
    jsondata = json.dumps(data)
    return HttpResponse(jsondata, content_type='application/json')


def validate(request, user, code):
    u = User.objects.get(username=user)
    u_meta = json.loads(u.userdata.metadata)
    if constant_time_compare(u_meta.get('code'), code):
        u_meta.update({ 'email_verified': True })
        u.userdata.metadata = json.dumps(u_meta)
        u.save()

        # giving perms
        acl = ACL(user=u.userdata, obj_type='Vote', perm='create',
                objectid=u.userdata.event.id)
        acl.save()
        data = {'status': 'ok', 'username': u.username}
        status = 200
    else:
        data = {'status': 'nok'}
        status = 400

    jsondata = json.dumps(data)
    return HttpResponse(jsondata, status=status, content_type='application/json')


class Email:
    DESCRIPTION = 'Register by email. You need to confirm your email.'
    TPL_CONFIG = {
            'subject': 'Confirm your email',
            'msg': 'Click in this link for validate your email: ',
            'mail_from': 'authapi@agoravoting.com'
    }

    def login_error(self):
        d = {'status': 'nok'}
        return d

    def login(self, data):
        d = {'status': 'ok'}
        user = data['user']
        pwd = data['password']

        try:
            u = User.objects.get(username=user)
        except:
            return self.login_error()

        u_meta = json.loads(u.userdata.metadata)
        if not u.check_password(pwd) or not u_meta.get('email_verified'):
            return self.login_error()

        d['auth-token'] = genhmac(settings.SHARED_SECRET, user)
        return d

    views = patterns('',
        url(r'^register/(?P<method>\d+)$', register),
        url(r'^validate/(?P<user>\w+)/(?P<code>\w+)$', validate),
    )

register_method('email', Email)
