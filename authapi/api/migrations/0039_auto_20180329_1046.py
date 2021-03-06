# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-03-29 10:46
from __future__ import unicode_literals

import django.contrib.postgres.fields.jsonb
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0038_auto_20180318_1624'),
    ]

    operations = [
        migrations.AddField(
            model_name='authevent',
            name='allow_public_census_query',
            field=models.BooleanField(default=True),
        ),
        migrations.AlterField(
            model_name='action',
            name='metadata',
            field=django.contrib.postgres.fields.jsonb.JSONField(default=dict),
        ),
        migrations.AlterField(
            model_name='userdata',
            name='metadata',
            field=django.contrib.postgres.fields.jsonb.JSONField(blank=True, default=dict, null=True),
        ),
    ]
