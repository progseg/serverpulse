# Generated by Django 3.2.19 on 2023-06-10 01:37

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0003_alter_admonglobal_timestamp_token_double_auth'),
    ]

    operations = [
        migrations.AlterField(
            model_name='admonglobal',
            name='timestamp_token_double_auth',
            field=models.DateTimeField(default=datetime.datetime(2023, 6, 10, 7, 37, 19, 311748, tzinfo=utc)),
        ),
    ]
