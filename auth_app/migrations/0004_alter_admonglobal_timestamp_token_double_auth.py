# Generated by Django 4.1.5 on 2023-06-06 17:30

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0003_alter_admonglobal_timestamp_token_double_auth'),
    ]

    operations = [
        migrations.AlterField(
            model_name='admonglobal',
            name='timestamp_token_double_auth',
            field=models.DateTimeField(default=datetime.datetime(
                2023, 6, 6, 17, 30, 4, 723450, tzinfo=datetime.timezone.utc)),
        ),
    ]