# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2017-11-05 19:27
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0030_userdata_draft_election'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='authevent',
            name='real',
        ),
    ]
