# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2017-11-04 13:59
from __future__ import unicode_literals

import django.contrib.postgres.fields.jsonb
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0029_auto_20171104_1356'),
    ]

    operations = [
        migrations.AddField(
            model_name='userdata',
            name='draft_election',
            field=django.contrib.postgres.fields.jsonb.JSONField(blank=True, db_index=False, default=dict, null=True),
        ),
    ]
