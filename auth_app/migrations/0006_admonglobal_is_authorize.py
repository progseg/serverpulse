# Generated by Django 4.1.5 on 2023-06-04 02:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0005_alter_admonglobal_chat_id_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='admonglobal',
            name='is_authorize',
            field=models.BooleanField(default=False),
        ),
    ]