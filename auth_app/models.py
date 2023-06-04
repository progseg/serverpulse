import string
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from datetime import datetime, timezone


class AdmonGlobal(models.Model):

    # Basic auth info
    user_name = models.CharField(
        max_length=50, unique=True, primary_key=True)
    passwd = models.CharField(max_length=15, unique=True)

    # Telegram basic info
    chat_id = models.CharField(
        max_length=10, unique=True, blank=True, null=True)

    # Tokens
    token_session = models.CharField(
        max_length=50, null=True, blank=True, unique=True, default=None)
    token_bot = models.CharField(
        max_length=50, unique=True, blank=True, null=True)
    token_double_auth = models.CharField(
        max_length=24, unique=True, default='default')

    # Intentos
    intentos = models.IntegerField(
        default=0, validators=[MinValueValidator(0), MaxValueValidator(4)])

    # Timestamps
    timestamp_ultimo_intento = models.DateTimeField(blank=True, null=True)
    timestamp_token_double_auth = models.DateTimeField(
        default=datetime.now(timezone.utc))

    # IPv4
    ipv4_address = models.GenericIPAddressField(
        protocol='IPv4', blank=True, null=True)

    # Authorize by superuser or webmaster
    is_authorize = models.BooleanField(default=False)


class Sysadmin(models.Model):
    nickname = models.CharField(max_length=15, unique=True, primary_key=True)
    password = models.CharField(max_length=15, unique=True)
    chat_id = models.CharField(max_length=10, unique=True)
    token_bot = models.CharField(max_length=50, unique=True)
    token_double_auth = models.CharField(max_length=24, unique=True)
    intentos = models.IntegerField(
        default=0, validators=[MinValueValidator(0), MaxValueValidator(4)])
    timestamp_ultimo_intento = models.DateTimeField()
    timestamp_token_double_auth = models.DateTimeField()
    ipv4_address = models.GenericIPAddressField(protocol='IPv4')
    autorize_account = models.BooleanField(default=False)


class Servidor(models.Model):

    ON_WORK_CHOISES = [
        (0, 'Indeterminado'),
        (1, 'Activo'),
        (2, 'Apagado')
    ]

    sysadmin = models.ForeignKey(Sysadmin, on_delete=models.CASCADE)
    ipv4_address = models.GenericIPAddressField(protocol='IPv4', unique=True)
    password = models.CharField(max_length=15, unique=True)
    status = models.IntegerField(default=0, validators=[MinValueValidator(
        0), MaxValueValidator(2)], choices=ON_WORK_CHOISES)
