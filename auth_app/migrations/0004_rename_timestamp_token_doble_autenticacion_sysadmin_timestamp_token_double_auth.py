# Generated by Django 4.1.5 on 2023-05-31 18:34

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0003_rename_token_doble_autenticacion_admonglobal_token_double_auth_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='sysadmin',
            old_name='timestamp_token_doble_autenticacion',
            new_name='timestamp_token_double_auth',
        ),
    ]
