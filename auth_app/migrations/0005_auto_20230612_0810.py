# Generated by Django 3.2.19 on 2023-06-12 08:10

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0004_alter_admonglobal_timestamp_token_double_auth'),
    ]

    operations = [
        migrations.AlterField(
            model_name='admonglobal',
            name='timestamp_token_double_auth',
            field=models.DateTimeField(default=datetime.datetime(2023, 6, 12, 14, 10, 46, 389127, tzinfo=utc)),
        ),
        migrations.AlterField(
            model_name='sysadmin',
            name='chat_id',
            field=models.CharField(blank=True, max_length=10, null=True, unique=True),
        ),
        migrations.AlterField(
            model_name='sysadmin',
            name='ipv4_address',
            field=models.GenericIPAddressField(blank=True, null=True, protocol='IPv4'),
        ),
        migrations.AlterField(
            model_name='sysadmin',
            name='timestamp_token_double_auth',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='sysadmin',
            name='timestamp_ultimo_intento',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='sysadmin',
            name='token_bot',
            field=models.CharField(blank=True, max_length=50, null=True, unique=True),
        ),
        migrations.AlterField(
            model_name='sysadmin',
            name='token_double_auth',
            field=models.CharField(blank=True, max_length=24, null=True, unique=True),
        ),
    ]