from django import forms
from . import validators
from auth_app.models import Servidor, Sysadmin
from captcha.fields import ReCaptchaField
from captcha.widgets import ReCaptchaV2Checkbox

USERNAME_MAX_LEN = 20
USERNAME_MIN_LEN = 4

PASSWD_MAX_LEN = 24
PASSWD_MIN_LEN = 12

LEN_TOKEN_BOT = 46
LEN_CHATID = 10

LEN_TOKEN2FA = 24

class SinginAdmin(forms.Form):
    user_name = forms.CharField(
        label='Nombre Sys Admin ',
        max_length=USERNAME_MAX_LEN,
        min_length=USERNAME_MIN_LEN,
        required=True,
        validators=[
            validators.validate_username,
            validators.contains_spaces,
        ]
    )
    passwd = forms.CharField(
        label='Contraseña',
        max_length=PASSWD_MAX_LEN,
        min_length=PASSWD_MIN_LEN,
        required=True,
        widget=forms.PasswordInput,
        validators=[
            validators.contains_digits,
            validators.contains_lowecase,
            validators.contains_uppercase,
            validators.contais_special,
            validators.contains_spaces,
        ]
    )
    repeat_passwd = forms.CharField(
        label='Repetir contraseña',
        max_length=PASSWD_MAX_LEN,
        min_length=PASSWD_MIN_LEN,
        required=True,
        widget=forms.PasswordInput,
        validators=[
            validators.contains_digits,
            validators.contains_lowecase,
            validators.contains_uppercase,
            validators.contais_special,
            validators.contains_spaces,
        ]
    )
    chat_id = forms.CharField(
        label='ID de su chat con su bot en Telegram',
        max_length=LEN_CHATID,
        min_length=LEN_CHATID,
        required=True,
        validators=[
            validators.only_digits,
            validators.contains_spaces,
        ]
    )
    token_bot = forms.CharField(
        label='Token de su BOT en Telegram',
        max_length=LEN_TOKEN_BOT,
        min_length=LEN_TOKEN_BOT,
        required=True,
        validators=[
            validators.telegram_bot_token,
            validators.contains_spaces,
        ]
    )
    captcha = ReCaptchaField(
        widget=ReCaptchaV2Checkbox
    )


class SinginServer(forms.Form):
    ipv4_address = forms.CharField(
        label='Dirección IP del Servidor',
        required=True,
        validators=[
            validators.validate_ipv46_address,
        ]
    )
    sysadmin = forms.CharField(
        label='Sys Admin asociado al Servidor',
        required=True,
        widget=forms.Select,
    )
    passwd = forms.CharField(
        label='Contraseña',
        max_length=PASSWD_MAX_LEN,
        min_length=PASSWD_MIN_LEN,
        required=True,
        widget=forms.PasswordInput,
        validators=[
            validators.contains_digits,
            validators.contains_lowecase,
            validators.contains_uppercase,
            validators.contais_special,
            validators.contains_spaces,
        ]
    )
    repeat_passwd = forms.CharField(
        label='Repetir contraseña',
        max_length=PASSWD_MAX_LEN,
        min_length=PASSWD_MIN_LEN,
        required=True,
        widget=forms.PasswordInput,
        validators=[
            validators.contains_digits,
            validators.contains_lowecase,
            validators.contains_uppercase,
            validators.contais_special,
            validators.contains_spaces,
        ]
    )
    captcha = ReCaptchaField(
        widget=ReCaptchaV2Checkbox
    )
