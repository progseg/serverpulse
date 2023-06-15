# Generated by Django 4.1.5 on 2023-06-14 15:28

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
    ]

    operations = [
        migrations.CreateModel(
            name='Salt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('object_id', models.PositiveBigIntegerField()),
                ('salt_value', models.CharField(max_length=24)),
                ('content_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='contenttypes.contenttype')),
            ],
        ),
        migrations.CreateModel(
            name='Sysadmin',
            fields=[
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ('user_name', models.CharField(max_length=20, unique=True)),
                ('passwd', models.CharField(max_length=24)),
                ('chat_id', models.CharField(blank=True, max_length=10, null=True, unique=True)),
                ('token_bot', models.CharField(blank=True, max_length=46, null=True, unique=True)),
                ('token_double_auth', models.CharField(blank=True, max_length=24, null=True, unique=True)),
                ('intentos', models.IntegerField(default=0, validators=[django.core.validators.MinValueValidator(0), django.core.validators.MaxValueValidator(4)])),
                ('timestamp_ultimo_intento', models.DateTimeField(blank=True, null=True)),
                ('timestamp_token_double_auth', models.DateTimeField(blank=True, null=True)),
                ('ipv4_address', models.GenericIPAddressField(blank=True, null=True, protocol='IPv4')),
                ('salt', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='sysadmin', to='auth_app.salt')),
            ],
        ),
        migrations.CreateModel(
            name='Servidor',
            fields=[
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ('ipv4_address', models.GenericIPAddressField(protocol='IPv4', unique=True)),
                ('password', models.CharField(max_length=24, unique=True)),
                ('status', models.IntegerField(choices=[(0, 'Indeterminado'), (1, 'Activo'), (2, 'Apagado')], default=0, validators=[django.core.validators.MinValueValidator(0), django.core.validators.MaxValueValidator(2)])),
                ('sysadmin', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='servidores', to='auth_app.sysadmin')),
            ],
        ),
        migrations.CreateModel(
            name='AdmonGlobal',
            fields=[
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True)),
                ('user_name', models.CharField(max_length=20, unique=True)),
                ('passwd', models.CharField(max_length=24)),
                ('chat_id', models.CharField(blank=True, max_length=10, null=True, unique=True)),
                ('token_bot', models.CharField(blank=True, max_length=46, null=True, unique=True)),
                ('token_double_auth', models.CharField(blank=True, max_length=24, null=True, unique=True)),
                ('intentos', models.IntegerField(default=0, validators=[django.core.validators.MinValueValidator(0), django.core.validators.MaxValueValidator(4)])),
                ('timestamp_ultimo_intento', models.DateTimeField(blank=True, null=True)),
                ('timestamp_token_double_auth', models.DateTimeField(blank=True, null=True)),
                ('ipv4_address', models.GenericIPAddressField(blank=True, null=True, protocol='IPv4')),
                ('salt', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='admonglobal', to='auth_app.salt')),
            ],
        ),
    ]
