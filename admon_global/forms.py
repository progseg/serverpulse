from django import forms
from django.core import validators
from auth_app.validators import *
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

    def clean(self):
        cleaned_data = super().clean()

        passwd = cleaned_data.get('passwd')
        repeat_passwd = cleaned_data.get('repeat_passwd')

        if (passwd is None
                or repeat_passwd is None):
            self.add_error('repeat_passwd', 'Las contraseñas no pueden estar vacias')
        if (passwd != repeat_passwd):
            self.add_error('repeat_passwd', 'Las contraseñas no coinciden')
        
        return cleaned_data

    user_name = forms.CharField(
        label='Nombre Sys Admin ',
        max_length=USERNAME_MAX_LEN,
        min_length=USERNAME_MIN_LEN,
        required=True,
        validators=[
            contains_spaces,
            validate_username,
        ]
    )
    passwd = forms.CharField(
        label='Contraseña',
        max_length=PASSWD_MAX_LEN,
        min_length=PASSWD_MIN_LEN,
        required=True,
        widget=forms.PasswordInput,
        validators=[
            contains_digits,
            contains_lowecase,
            contains_uppercase,
            contais_special,
            contains_spaces,
        ]
    )
    repeat_passwd = forms.CharField(
        label='Repetir contraseña',
        max_length=PASSWD_MAX_LEN,
        min_length=PASSWD_MIN_LEN,
        required=True,
        widget=forms.PasswordInput,
        validators=[
            contains_digits,
            contains_lowecase,
            contains_uppercase,
            contais_special,
            contains_spaces,
        ]
    )
    chat_id = forms.CharField(
        label='ID de su chat con su bot en Telegram',
        max_length=LEN_CHATID,
        min_length=LEN_CHATID,
        required=True,
        validators=[
            only_digits,
            contains_spaces,
        ]
    )
    token_bot = forms.CharField(
        label='Token de su BOT en Telegram',
        max_length=LEN_TOKEN_BOT,
        min_length=LEN_TOKEN_BOT,
        required=True,
        validators=[
            telegram_bot_token,
            contains_spaces,
        ]
    )
    captcha = ReCaptchaField(
        widget=ReCaptchaV2Checkbox
    )


class UpdateSysadmin(forms.Form):
    user_name = forms.CharField(
        label='Nombre Sys Admin',
        max_length=SinginAdmin.base_fields['user_name'].max_length,
        min_length=SinginAdmin.base_fields['user_name'].min_length,
        required=False,
        validators=[
            contains_spaces,
            validate_username,
        ]
    )
    passwd = forms.CharField(
        label='Contraseña',
        max_length=SinginAdmin.base_fields['passwd'].max_length,
        min_length=SinginAdmin.base_fields['passwd'].min_length,
        required=False,
        widget=forms.PasswordInput,
        validators=[
            contains_digits,
            contains_lowecase,
            contains_uppercase,
            contais_special,
            contains_spaces,
        ]
    )
    repeat_passwd = forms.CharField(
        label='Repetir contraseña',
        max_length=SinginAdmin.base_fields['repeat_passwd'].max_length,
        min_length=SinginAdmin.base_fields['repeat_passwd'].min_length,
        required=False,
        widget=forms.PasswordInput,
        validators=[
            contains_digits,
            contains_lowecase,
            contains_uppercase,
            contais_special,
            contains_spaces,
        ]
    )
    chat_id = forms.CharField(
        label='ID de su chat con su bot en Telegram',
        max_length=SinginAdmin.base_fields['chat_id'].max_length,
        min_length=SinginAdmin.base_fields['chat_id'].min_length,
        required=False,
        validators=[
            only_digits,
            contains_spaces,
        ]
    )
    token_bot = forms.CharField(
        label='Token de su BOT en Telegram',
        max_length=SinginAdmin.base_fields['token_bot'].max_length,
        min_length=SinginAdmin.base_fields['token_bot'].min_length,
        required=False,
        validators=[
            telegram_bot_token,
            contains_spaces,
        ]
    )
    captcha = ReCaptchaField(
        widget=ReCaptchaV2Checkbox
    )

    def __init__(self, *args, **kwargs):
        self.instance = kwargs.pop('instance', None)
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()

        passwd = cleaned_data.get('passwd')
        repeat_passwd = cleaned_data.get('repeat_passwd')

        if ((passwd and repeat_passwd)
                and (passwd is None or repeat_passwd is None)):
            self.add_error('repeat_passwd', 'Las contraseñas no pueden estar vacias')
        if (passwd != repeat_passwd):
            self.add_error('repeat_passwd', 'Las contraseñas no coinciden')
        
        return cleaned_data

    def save(self):
        self.instance.user_name = self.cleaned_data['user_name']
        self.instance.passwd = self.cleaned_data['passwd']
        self.instance.chat_id = self.cleaned_data['chat_id']
        self.instance.token_bot = self.cleaned_data['token_bot']
        self.instance.save()
        return self.instance
    

class SinginServer(forms.ModelForm):
    ipv4_address = forms.CharField(
        label='Dirección IP del Servidor',
        required=True,
        validators=[
            validators.validate_ipv4_address,
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
            contains_digits,
            contains_lowecase,
            contains_uppercase,
            contais_special,
            contains_spaces,
        ]
    )
    repeat_passwd = forms.CharField(
        label='Repetir contraseña',
        max_length=PASSWD_MAX_LEN,
        min_length=PASSWD_MIN_LEN,
        required=True,
        widget=forms.PasswordInput,
        validators=[
            contains_digits,
            contains_lowecase,
            contains_uppercase,
            contais_special,
            contains_spaces
        ]
    )
    captcha = ReCaptchaField(
        widget=ReCaptchaV2Checkbox
    )
