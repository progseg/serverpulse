from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from uuid import uuid4
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType


USERNAME_MAX_LEN = 20
PASSWD_MAX_LEN = 128
LEN_TOKEN_BOT = 46
LEN_CHATID = 10
LEN_TOKEN2FA = 24
LEN_SALT = 128


class Salt(models.Model):
    salt_value = models.CharField(
        max_length=LEN_SALT
    )


class AdmonGlobal(models.Model):
    uuid = models.UUIDField(
        default=uuid4,
        editable=False,
        unique=True,
        primary_key=True
    )
    user_name = models.CharField(
        max_length=USERNAME_MAX_LEN,
        unique=True,
    )
    passwd = models.CharField(
        max_length=PASSWD_MAX_LEN
    )
    chat_id = models.CharField(
        max_length=LEN_CHATID,
        unique=True,
        blank=True,
        null=True
    )
    token_bot = models.CharField(
        max_length=LEN_TOKEN_BOT,
        unique=True,
        blank=True,
        null=True
    )
    token_double_auth = models.CharField(
        max_length=LEN_TOKEN2FA,
        unique=True,
        null=True,
        blank=True
    )
    intentos = models.IntegerField(
        default=0,
        validators=[
            MinValueValidator(0),
            MaxValueValidator(4)
        ]
    )
    timestamp_ultimo_intento = models.DateTimeField(
        blank=True,
        null=True
    )
    timestamp_token_double_auth = models.DateTimeField(
        blank=True,
        null=True
    )
    ipv4_address = models.GenericIPAddressField(
        protocol='IPv4',
        blank=True,
        null=True
    )
    salt = models.OneToOneField(
        Salt,
        on_delete=models.CASCADE,
        related_name='admonglobal'
    )


class Sysadmin(models.Model):
    uuid = models.UUIDField(
        default=uuid4,
        editable=False,
        unique=True,
        primary_key=True
    )
    user_name = models.CharField(
        max_length=USERNAME_MAX_LEN,
        unique=True
    )
    passwd = models.CharField(
        max_length=PASSWD_MAX_LEN
    )
    chat_id = models.CharField(
        max_length=LEN_CHATID,
        unique=True,
        blank=True,
        null=True
    )
    token_bot = models.CharField(
        max_length=LEN_TOKEN_BOT,
        unique=True,
        blank=True,
        null=True
    )
    token_double_auth = models.CharField(
        max_length=LEN_TOKEN2FA,
        unique=True,
        blank=True,
        null=True
    )
    intentos = models.IntegerField(
        default=0,
        validators=[
            MinValueValidator(0),
            MaxValueValidator(4)
        ]
    )
    timestamp_ultimo_intento = models.DateTimeField(
        blank=True,
        null=True
    )
    timestamp_token_double_auth = models.DateTimeField(
        blank=True,
        null=True
    )
    ipv4_address = models.GenericIPAddressField(
        protocol='IPv4',
        blank=True,
        null=True
    )
    salt = models.OneToOneField(
        Salt,
        on_delete=models.CASCADE,
        related_name='sysadmin'
    )


class Servidor(models.Model):
    ON_WORK_CHOISES = [
        (0, 'Indeterminado'),
        (1, 'Activo'),
        (2, 'Apagado')
    ]
    uuid = models.UUIDField(
        default=uuid4,
        editable=False,
        unique=True,
        primary_key=True,
    )
    sysadmin = models.ForeignKey(
        Sysadmin,
        on_delete=models.CASCADE,
        to_field= 'uuid',
        related_name= 'servidores'
    )
    ipv4_address = models.GenericIPAddressField(
        protocol='IPv4',
        unique=True
    )
    password = models.CharField(
        max_length=PASSWD_MAX_LEN,
        unique=True
    )
    status = models.IntegerField(
        default=0,
        validators=[
            MinValueValidator(0),
            MaxValueValidator(2)
        ],
    choices=ON_WORK_CHOISES,
    )