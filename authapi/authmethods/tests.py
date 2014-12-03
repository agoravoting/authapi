from django.contrib.auth.models import User
from django.core import mail
from django.test import TestCase

import json
import time
from api.tests import JClient
from api.models import AuthEvent, ACL
from .m_email import Email
from .m_sms import Sms


class AuthMethodTestCase(TestCase):
    def setUp(self):
        pass

    def test_method_custom_view(self):
        c = JClient()
        response = c.get('/api/authmethod/user-and-password/test/asdfdsf/', {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

        response = c.get('/api/authmethod/user-and-password/test/asdfdsf/cxzvcx/', {})
        self.assertEqual(response.status_code, 404)


class AuthMethodEmailTestCase(TestCase):
    def setUp(self):
        ae = AuthEvent(pk=1, name='test', auth_method='email',
                auth_method_config=json.dumps(Email.TPL_CONFIG))
        ae.save()

        u = User(pk=1, username='test1')
        u.set_password('123456')
        u.save()
        u.userdata.event = ae
        u.userdata.metadata = json.dumps({
                'email': 'test@test.com',
                'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                'email_verified': True
        })
        u.userdata.save()

        u2 = User(pk=2, username='test2')
        u2.set_password('123456')
        u2.save()
        u2.userdata.event = ae
        u2.userdata.metadata = json.dumps({
                'email': 'test2@test.com',
                'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                'email_verified': False
        })
        u2.userdata.save()


    def test_method_email_register(self):
        c = JClient()
        response = c.post('/api/authmethod/email/register/1/',
                {'email': 'test@test.com', 'user': 'test', 'password': '123456'})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

    def test_method_email_valid_code(self):
        user = 'test1'
        code = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

        c = JClient()
        response = c.get('/api/authmethod/email/validate/%s/%s/' % (user, code), {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

    def test_method_email_invalid_code(self):
        user = 'test1'
        code = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'

        c = JClient()
        response = c.get('/api/authmethod/email/validate/%s/%s/' % (user, code), {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'nok')

    def test_method_email_login_valid_code(self):
        c = JClient()
        response = c.post('/api/login/',
                {'auth-method': 'email', 'auth-data':
                    {'user': 'test1', 'password': '123456'}})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertTrue(r['auth-token'].startswith('khmac:///sha256'))

    def test_method_email_login_invalid_code(self):
        c = JClient()
        response = c.post('/api/login/',
                {'auth-method': 'email', 'auth-data':
                    {'user': 'test2', 'password': '123456'}})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'nok')


class AuthMethodSmsTestCase(TestCase):
    def setUp(self):
        ae = AuthEvent(pk=1, name='test', auth_method='sms-code',
                auth_method_config=json.dumps(Sms.TPL_CONFIG))
        ae.save()

        u = User(pk=1, username='test1')
        u.set_password('123456')
        u.save()
        u.userdata.event = ae
        u.userdata.metadata = json.dumps({
                'tlf': '+34666666666',
                'code': 'AAAAAAAA',
                'sms_verified': True
        })
        u.userdata.save()
        for perm in Sms.TPL_CONFIG.get('register-perm'):
            acl = ACL(user=u.userdata, perm=perm)
            acl.save()

        u2 = User(pk=2, username='test2')
        u2.set_password('123456')
        u2.save()
        u2.userdata.event = ae
        u2.userdata.metadata = json.dumps({
                'tlf': '+34766666666',
                'code': 'AAAAAAAA',
                'sms_verified': False
        })
        u2.userdata.save()
        self.c = JClient()
        pipe = Sms.TPL_CONFIG.get('register-pipeline')
        for p in pipe:
            if p[0] == 'check_total_max':
                if p[1].get('field') == 'tlf':
                    if p[1].get('period'):
                        self.period_tlf = p[1].get('period')
                        self.total_max_tlf_period = p[1].get('max')
                    else:
                        self.total_max_tlf = p[1].get('max')
                elif p[1].get('field') == 'ip':
                    self.total_max_ip = p[1].get('max')

    def test_method_sms_regiter(self):
        response = self.c.post('/api/authmethod/sms-code/register/1/',
                {'tlf': '+34666666666', 'password': '123456',
                    'email': 'test@test.com', 'dni': '11111111H'})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

    def test_method_sms_register_valid_dni(self):
        response = self.c.post('/api/authmethod/sms-code/register/1/',
                {'tlf': '+34666666666', 'password': '123456', 'dni': '11111111H'})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['msg'].find('Invalid dni'), -1)

    def test_method_sms_register_invalid_dni(self):
        response = self.c.post('/api/authmethod/sms-code/register/1/',
                {'tlf': '+34666666666', 'password': '123456', 'dni': '999'})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertNotEqual(r['msg'].find('Invalid dni'), -1)

    def test_method_sms_register_valid_email(self):
        response = self.c.post('/api/authmethod/sms-code/register/1/',
                {'tlf': '+34666666666', 'password': '123456',
                    'email': 'test@test.com'})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['msg'].find('Invalid email'), -1)

    def test_method_sms_register_invalid_email(self):
        response = self.c.post('/api/authmethod/sms-code/register/1/',
                {'tlf': '+34666666666', 'password': '123456', 'email': 'test@@'})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertNotEqual(r['msg'].find('Invalid email'), -1)

    def test_method_sms_valid_code(self):
        user = 'test1'
        code = 'AAAAAAAA'

        response = self.c.get('/api/authmethod/sms-code/validate/%s/%s/' % (user, code), {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

    def test_method_sms_invalid_code(self):
        user = 'test1'
        code = 'BBBBBBBB'

        response = self.c.get('/api/authmethod/sms-code/validate/%s/%s/' % (user, code), {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'nok')

    def test_method_sms_get_perm(self):
        auth = {
            'auth-method': 'sms-code',
            'auth-data': {
                'user': 'test1',
                'password': '123456'
            }
        }
        data1 = { "permission": "add_vote", }
        data2 = { "permission": "rm_vote", }

        response = self.c.post('/api/get-perms', data1)
        self.assertEqual(response.status_code, 301)
        response = self.c.post('/api/get-perms', data2)
        self.assertEqual(response.status_code, 301)

        self.c.login(auth)
        response = self.c.post('/api/get-perms/', data1)
        self.assertEqual(response.status_code, 200)
        response = self.c.post('/api/get-perms/', data2)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'nok')

    def test_method_sms_login_valid_code(self):
        response = self.c.post('/api/login/',
                {'auth-method': 'sms-code', 'auth-data':
                    {'user': 'test1', 'password': '123456'}})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertTrue(r['auth-token'].startswith('khmac:///sha256'))

    def test_method_sms_login_invalid_code(self):
        response = self.c.post('/api/login/',
                {'auth-method': 'sms-code', 'auth-data':
                    {'user': 'test2', 'password': '123456'}})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'nok')

    def test_method_sms_regiter_max_tlf(self):
        x = 0
        while x < self.total_max_tlf + 1:
            x += 1
            response = self.c.post('/api/authmethod/sms-code/register/1/',
                    {'tlf': '+34666666666', 'password': '123456',
                        'email': 'test@test.com', 'dni': '11111111H'})
        response = self.c.post('/api/authmethod/sms-code/register/1/',
                {'tlf': '+34666666666', 'password': '123456',
                    'email': 'test@test.com', 'dni': '11111111H'})
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertNotEqual(r['message'].find('Blacklisted'), -1)

    def test_method_sms_regiter_max_tlf_period(self):
        x = 0
        time_now = time.time()
        while x < self.total_max_tlf_period + 1:
            x += 1
            response = self.c.post('/api/authmethod/sms-code/register/1/',
                    {'tlf': '+34666666666', 'password': '123456',
                        'email': 'test@test.com', 'dni': '11111111H'})
        response = self.c.post('/api/authmethod/sms-code/register/1/',
                {'tlf': '+34666666666', 'password': '123456',
                    'email': 'test@test.com', 'dni': '11111111H'})

        total_time = time.time() - time_now
        if total_time < self.period_tlf:
            self.assertEqual(response.status_code, 400)
            r = json.loads(response.content.decode('utf-8'))
            self.assertNotEqual(r['message'].find('Blacklisted'), -1)
        else:
            self.assertEqual(response.status_code, 200)