import logging
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from uuid import uuid4
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
import re
import bcrypt
from django.utils.html import escape


USERNAME_MAX_LEN = 20
PASSWD_MAX_LEN = 128
LEN_TOKEN_BOT = 46
LEN_CHATID = 10
LEN_TOKEN2FA = 24
LEN_SALT = 128

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO,
                    filename='resgistros.log', filemode='a')


def clean_specials(clean_data):
    escaped_data = {}
    for field_name, field_value in clean_data.items():
        escaped_data[field_name] = escape(field_value)
    return escaped_data


def gen_salt():
    try:
        salt = bcrypt.gensalt()
        return salt.decode()
    except Exception as e:
        logging.error(e)


def derivate_passwd(salt, passwd):
    salt_bytes = salt.encode()
    passwd_bytes = passwd.encode()

    try:
        hashed_passwd = bcrypt.hashpw(passwd_bytes, salt_bytes)
        return hashed_passwd.decode()
    except Exception as e:
        logging.error(e)


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
        related_name='admonglobal',
        blank= True,
        null= True
    )

    def delete(self, *args, **kwargs):
        if self.salt:
            self.salt.delete()
        
        super().delete(*args, **kwargs)

    def save(self, *args, **kwargs):
        logging.info('Entró a save')
        salt = gen_salt()
        logging.info(f'salt={salt}')
        hashed_passwd= derivate_passwd(salt, self.passwd)
        logging.info(f'hashed_passwd={hashed_passwd}')
        try:
            salt_model = Salt.objects.create(salt_value = salt)
        except Exception as e:
            logging.error(f'create Salt Instance = {e}')
        logging.info(f'salt_model={salt_model}')
        self.salt = salt_model
        logging.info(f'self.salt = {self.salt}')
        self.passwd = hashed_passwd
        logging.info(f'self.passwd={self.passwd}')
        logging.info(f'self.uuid={self.uuid}')
        logging.info(f'self.chat_id={self.chat_id}')
        logging.info(f'self.token_bot={self.token_bot}')
        super().save(*args, **kwargs)


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

    def delete(self, *args, **kwargs):
        if self.salt:
            self.salt.delete()
        
        super().delete(*args, **kwargs)


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
    ipv4_address = models.GenericIPAddressField(
        protocol='IPv4',
        unique=True
    )
    passwd = models.CharField(
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
    sysadmin = models.ForeignKey(
        Sysadmin,
        related_name='servidores',
        on_delete=models.PROTECT,
        blank= True,
        null= True,
        default= None
    )
    salt = models.OneToOneField(
        Salt,
        on_delete=models.CASCADE,
        related_name='servidores'
    )

    def delete(self, *args, **kwargs):
        if self.salt:
            self.salt.delete()
        
        super().delete(*args, **kwargs)