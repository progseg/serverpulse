# Generated by Django 4.1.5 on 2023-06-04 03:17

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0007_alter_admonglobal_token_bot'),
    ]

    operations = [
        migrations.AlterField(
            model_name='admonglobal',
            name='timestamp_token_double_auth',
            field=models.DateTimeField(default=datetime.datetime(2023, 6, 4, 3, 17, 17, 93900, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='admonglobal',
            name='token_double_auth',
            field=models.CharField(default='default', max_length=24, unique=True),
        ),
    ]