# Generated by Django 4.1.5 on 2023-06-12 00:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0013_alter_admonglobal_token_double_auth'),
    ]

    operations = [
        migrations.AlterField(
            model_name='admonglobal',
            name='passwd',
            field=models.CharField(max_length=24, unique=True),
        ),
    ]
