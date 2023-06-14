from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from uuid import uuid4


USERNAME_MAX_LEN = 20
PASSWD_MAX_LEN = 24
LEN_TOKEN_BOT = 46
LEN_CHATID = 10
LEN_TOKEN2FA = 24


class AdmonGlobal(models.Model):

    # Basic auth info
    user_name = models.CharField(
        max_length=USERNAME_MAX_LEN,
        unique=True,
        primary_key=True
    )
    passwd = models.CharField(
        max_length=PASSWD_MAX_LEN
    )
    # Telegram basic info
    chat_id = models.CharField(
        max_length=LEN_CHATID,
        unique=True,
        blank=True,
        null=True
    )
    # Tokens
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
    # Intentos
    intentos = models.IntegerField(
        default=0,
        validators=[
            MinValueValidator(0),
            MaxValueValidator(4)
        ]
    )
    # Timestamps
    timestamp_ultimo_intento = models.DateTimeField(
        blank=True,
        null=True
    )
    timestamp_token_double_auth = models.DateTimeField(
        blank=True,
        null=True
    )
    # IPv4
    ipv4_address = models.GenericIPAddressField(
        protocol='IPv4',
        blank=True,
        null=True
    )


class Sysadmin(models.Model):
    user_name = models.CharField(
        max_length=USERNAME_MAX_LEN,
        unique=True,
        primary_key=True
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
    uuid = models.UUIDField(
        default=uuid4,
        editable=False,
        unique=True
    )


class Servidor(models.Model):
    ON_WORK_CHOISES = [
        (0, 'Indeterminado'),
        (1, 'Activo'),
        (2, 'Apagado')
    ]
    sysadmin = models.ForeignKey(
        Sysadmin,
        on_delete=models.CASCADE
    )
    ipv4_address = models.GenericIPAddressField(
        protocol='IPv4',
        unique=True
    )
    password = models.CharField(
        max_length=15,
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
    uuid = models.UUIDField(
        default=uuid4,
        editable=False,
        unique=True
    )