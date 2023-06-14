# Generated by Django 4.1.5 on 2023-06-12 01:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0015_rename_password_sysadmin_passwd_and_more'),
    ]

    operations = [
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