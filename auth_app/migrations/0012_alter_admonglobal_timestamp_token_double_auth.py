# Generated by Django 4.1.5 on 2023-06-04 05:25

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0011_alter_admonglobal_timestamp_token_double_auth'),
    ]

    operations = [
        migrations.AlterField(
            model_name='admonglobal',
            name='timestamp_token_double_auth',
            field=models.DateTimeField(default=datetime.datetime(2023, 6, 4, 5, 25, 25, 614271, tzinfo=datetime.timezone.utc)),
        ),
    ]
