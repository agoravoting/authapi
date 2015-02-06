pwd_auth = {'username': 'john', 'password': 'smith'}

pwd_auth_email = {'email': 'john@agoravoting.com', 'password': 'smith'}

auth_event1 = {
    "auth_method": "sms",
    "census": "close",
    "auth_method_config": {"msg": "Enter in %(url)s and put this code %(code)s"},
    "extra_fields": [
            {
            "name": "name",
            "help": "put the name that appear in your dni",
            "type": "text",
            "required": True,
            "max": 2,
            "max": 64,
            "required_on_authentication": True
            },
            {
            "name": "email",
            "type": "email",
            "required": True,
            "min": 4,
            "max": 255,
            "required_on_authentication": True
            },
            {
            "name": "dni",
            "help": "put the dni without dash",
            "type": "text",
            "required": True,
            "max": 9,
            "max": 9,
            "required_on_authentication": True
            }
    ]
}

auth_event2 = {
    "auth_method": "sms",
    "census": "open",
    "auth_method_config": {"msg": "Enter in %(url)s and put this code %(code)s"},
    "extra_fields": [
            {
            "name": "name",
            "help": "put the name that appear in your dni",
            "type": "text",
            "required": False,
            "min": 2,
            "max": 64,
            "required_on_authentication": False
            },
            {
            "name": "age",
            "help": "put the age",
            "type": "int",
            "required": False,
            "min": 18,
            "max": 150,
            "required_on_authentication": False
            },
            {
            "name": "email",
            "type": "email",
            "required": True,
            "min": 4,
            "max": 255,
            "required_on_authentication": True
            },
            {
            "name": "dni",
            "help": "put the dni without dash",
            "type": "text",
            "required": True,
            "max": 9,
            "max": 9,
            "required_on_authentication": True
            }
    ]
}

auth_event3 = {
    "auth_method": "email",
    "census": "open",
    "auth_method_config": {
        "subject": "Confirm your email",
        "msg": "Click %(url)s and put this code %(code)s"
    }
}

auth_event4 = {
    "auth_method": "user-and-password",
    "census": "open"
}

auth_event5 = {
    "auth_method": "user-and-password",
    "census": "open",
    "auth_method_config": {},
    "extra_fields": [
            {
            "name": "name",
            "type": "text",
            "required": True,
            "max": 2,
            "max": 64,
            "required_on_authentication": True
            },
    ]
}

# Users
admin = {'username': 'john', 'password': 'smith'}

# Census
census_email_default = [
        {"email": "baaa@aaa.com"},
        {"email": "caaa@aaa.com"},
        {"email": "daaa@aaa.com"},
        {"email": "eaaa@aaa.com"}
]

census_email_fields = [
        {"name": "aaaa", "email": "baaa@aaa.com"},
        {"name": "baaa", "email": "caaa@aaa.com"},
        {"name": "caaa", "email": "daaa@aaa.com"},
        {"name": "daaa", "email": "eaaa@aaa.com"}
]

census_email_repeat = [
        {"email": "repeat@aaa.com"},
        {"email": "repeat@aaa.com"}
]

census_sms_default = [
        {"tlf": "666666667"},
        {"tlf": "666666668"},
        {"tlf": "666666669"},
        {"tlf": "666666670"}
]

census_sms_fields = [
        {"name": "aaaa", "tlf": "666666665"},
        {"name": "baaa", "tlf": "666666667"},
        {"name": "caaa", "tlf": "666666668"},
        {"name": "daaa", "tlf": "666666669"}
]

census_sms_repeat = [
        {"tlf": "777777777"},
        {"tlf": "777777777"}
]

# Register
register_email_default = {"email": "bbbb@aaa.com", "captcha": "asdasd"}

register_email_fields = {"name": "aaaa", "email": "bbbb@aaa.com", "captcha": "asdasd"}

register_sms_default = {"tlf": "666666667", "captcha": "asdasd"}

register_sms_fields = {"name": "aaaa", "tlf": "666666667", "captcha": "asdasd"}

sms_fields_incorrect_type1 = {"age": "a lot"}
sms_fields_incorrect_type2 = {"tlf": 666666667}
sms_fields_incorrect_len1 = {"age": 16}
sms_fields_incorrect_len2 = {"name": 100*"n"}

# Authenticate
auth_email_default = {
        "email": "aaaa@aaa.com",
        "code": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

auth_email_fields = {
        "name": "aaaa",
        "email": "aaaa@aaa.com",
        "code": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

auth_sms_default = {
        "tlf": "666666666",
        "code": "123456"
}

auth_sms_fields = {
        "name": "aaaa",
        "tlf": "666666666",
        "code": "123456"
}

# Authmethod config
pipe_total_max_ip =  8
pipe_total_max_tlf = 4
pipe_total_max_tlf_with_period = 60
pipe_total_max_period = 60
pipe_times = 5
pipe_timestamp = 5

authmethod_config_email_default = {
        "auth_method_config": {
            "subject": "Confirm your email",
            "msg": "Click %(url)s and put this code %(code)s"
        },
        "pipeline": {
            "register-pipeline": [
                ["check_whitelisted", {"field": "ip"}],
                ["check_blacklisted", {"field": "ip"}],
                ["check_total_max", {"field": "ip", "max": pipe_total_max_ip}],
            ],
            "authenticate-pipeline": [
                #['check_total_connection', {'times': pipe_times }],
            ]
        }
}

authmethod_config_sms_default = {
        "auth_method_config": {
            "SMS_PROVIDER": "console",
            "SMS_DOMAIN_ID": "",
            "SMS_LOGIN": "",
            "SMS_PASSWORD": "",
            "SMS_URL": "",
            "SMS_SENDER_ID": "",
            "SMS_VOICE_LANG_CODE": "",
            "msg": "Enter in %(url)s and put this code %(code)s"
        },
        "pipeline": {
            "register-pipeline": [
                ["check_whitelisted", {"field": "tlf"}],
                ["check_whitelisted", {"field": "ip"}],
                ["check_blacklisted", {"field": "ip"}],
                ["check_blacklisted", {"field": "tlf"}],
                ["check_total_max", {"field": "ip", "max": pipe_total_max_ip}],
                ["check_total_max", {"field": "tlf", "max": pipe_total_max_tlf}],
                ["check_total_max", {"field": "tlf", "period": pipe_total_max_period, "max": pipe_total_max_tlf_with_period}],
            ],
            "authenticate-pipeline": [
                #['check_total_connection', {'times': pipe_times }],
                ['check_sms_code', {'timestamp': pipe_timestamp }]
            ]
        }
}

# Authevent
ae_email_default = {
    "auth_method": "email",
    "census": "open",
}

ae_incorrect_authmethod = ae_email_default.copy()
ae_incorrect_authmethod.update({"auth_method": "a"})

ae_incorrect_census = ae_email_default.copy()
ae_incorrect_census.update({"census": "a"})

ae_without_authmethod = ae_email_default.copy()
ae_without_authmethod.pop("auth_method")

ae_without_census = ae_email_default.copy()
ae_without_census.pop("census")

ae_email_config = ae_email_default.copy()
ae_email_config.update( {
    "auth_method_config": {
        "subject": "Vote",
        "msg": "Enter in %(url)s and put this code %(code)s",
    }
})

ae_email_config_incorrect1 = ae_email_config.copy()
ae_email_config_incorrect1.update({"auth_method_config": {"aaaaaa": "bbbb"}})

ae_email_config_incorrect2 = ae_email_config.copy()
ae_email_config_incorrect2.update({"auth_method_config": "aaaaaa"})


ae_email_fields = ae_email_default.copy()
ae_email_fields.update( {
    "extra_fields": [
            {
            "name": "name",
            "help": "put the name that appear in your dni",
            "type": "text",
            "required": True,
            "min": 2,
            "max": 64,
            "required_on_authentication": True
            }
    ]
})

ae_email_fields_captcha = ae_email_fields.copy()
ae_email_fields_captcha.update( {'extra_fields': [{'name': 'captcha', 'type': 'captcha',
        'required': True, 'required_on_authentication': False}]})

ae_email_fields_incorrect_max_fields = ae_email_fields.copy()
ae_email_fields_incorrect_max_fields.update({"extra_fields": [{"boo": True},
    {"boo": True}, {"boo": True}, {"boo": True}, {"boo": True}, {"boo": True},
    {"boo": True}, {"boo": True}, {"boo": True}, {"boo": True}, {"boo": True},
    {"boo": True}, {"boo": True}, {"boo": True}, {"boo": True}, {"boo": True}]})

ae_email_fields_incorrect_empty = ae_email_fields.copy()
ae_email_fields_incorrect_empty.update( {'extra_fields': [{'name': '', 'type': 'text', 'required_on_authentication': False}]})

ae_email_fields_incorrect_len1 = ae_email_fields.copy()
ae_email_fields_incorrect_len1.update( {'extra_fields': [{'name': 256*'i', 'type': 'text', 'required_on_authentication': False}]})

from sys import maxsize
ae_email_fields_incorrect_len2 = ae_email_fields.copy()
ae_email_fields_incorrect_len2.update( {'extra_fields': [{'name': 'iii', 'type': 'text', 'required_on_authentication': False, 'max': maxsize + 1}]})

ae_email_fields_incorrect_type = ae_email_fields.copy()
ae_email_fields_incorrect_type.update( {'extra_fields': [{'name': 'name', 'type': 'null', 'required_on_authentication': False}]})

ae_email_fields_incorrect_value_int = ae_email_fields.copy()
ae_email_fields_incorrect_value_int.update( {'extra_fields': [{'name': 'name', 'type': 'text', 'required_on_authentication': False, 'min': '1'}]})

ae_email_fields_incorrect_value_bool = ae_email_fields.copy()
ae_email_fields_incorrect_value_bool.update( {'extra_fields': [{'name': 'name', 'type': 'text', 'required_on_authentication': 'False'}]})

ae_email_fields_incorrect = ae_email_fields.copy()
ae_email_fields_incorrect.update({"extra_fields": [{'name': 'name', 'type': 'text', 'required_on_authentication': False, "boo": True}]})

ae_email_fields_incorrect_repeat = ae_email_fields.copy()
ae_email_fields_incorrect_repeat.update( {'extra_fields': [
    {'name': 'surname', 'type': 'text', 'required_on_authentication': False},
    {'name': 'surname', 'type': 'text', 'required_on_authentication': False}]})

ae_email_fields_incorrect_email = ae_email_fields.copy()
ae_email_fields_incorrect_email.update( {'extra_fields': [
    {'name': 'email', 'type': 'email', 'required_on_authentication': False}]})

ae_sms_default = {
    "auth_method": "sms",
    "census": "open",
}

ae_sms_config = {
    "auth_method": "sms",
    "census": "open",
    "auth_method_config": {"msg": "Enter in %(url)s and put this code %(code)s"}
}

ae_sms_fields = {
    "auth_method": "sms",
    "census": "open",
    "extra_fields": [
            {
            "name": "name",
            "help": "put the name that appear in your dni",
            "type": "text",
            "required": True,
            "max": 2,
            "max": 64,
            "required_on_authentication": True
            }
    ]
}

ae_sms_fields_incorrect_tlf = ae_sms_default.copy()
ae_sms_fields_incorrect_tlf.update( {'extra_fields': [
    {'name': 'tlf', 'type': 'tlf', 'required_on_authentication': False}]})

ae_sms_config_incorrect = {
    "auth_method": "sms",
    "census": "open",
    "auth_method_config": {"incorrect": "sms code: {code}"}
}

ae_sms_fields_incorrect = {
    "auth_method": "sms",
    "census": "open",
    "extra_fields": [
            {"boo": True}
    ]
}
