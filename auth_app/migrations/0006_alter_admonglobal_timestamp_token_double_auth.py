# Generated by Django 3.2.19 on 2023-06-12 20:41

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0005_auto_20230612_0810'),
    ]

    operations = [
        migrations.AlterField(
            model_name='admonglobal',
            name='timestamp_token_double_auth',
            field=models.DateTimeField(default=datetime.datetime(2023, 6, 13, 2, 41, 22, 255699, tzinfo=utc)),
        ),
    ]
