import re
from typing import Any, Dict
from django import forms
from .models import *
from . import views
from . import validators
from django.contrib.auth.forms import AuthenticationForm
from django.forms import ValidationError
from django.contrib.auth.hashers import make_password
from captcha.fields import ReCaptchaField
from captcha.widgets import ReCaptchaV2Checkbox

USERNAME_MAX_LEN = 20
USERNAME_MIN_LEN = 4

PASSWD_MAX_LEN = 24
PASSWD_MIN_LEN = 12

LEN_TOKEN_BOT = 46
LEN_CHATID = 10

LEN_TOKEN2FA = 24


class Singin(forms.Form):
    nick_name = forms.CharField(
        label='nombre único de usuario',
        max_length=USERNAME_MAX_LEN,
        min_length=USERNAME_MIN_LEN,
        required=True,
        validators=[
            validators.validate_username,
            validators.contains_spaces,
        ]
    )
    passwd = forms.CharField(
        label='contraseña',
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
        label='token de su bot en Telegram',
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

    def save(self, commit=True):
        # Se redefine la forma en que se guarda la contraseña
        user = super().save(commit=False)
        password_hash = views.hashear_password(self.cleaned_data['password'])
        user.password = password_hash
        if commit:
            user.save()
        return user


class Login(forms.Form):
    user_name = forms.CharField(
        label='username',
        max_length=USERNAME_MAX_LEN,
        min_length=USERNAME_MIN_LEN,
        required=True,
        widget=forms.TextInput(
            attrs={
                'name': 'user_name',
                'id': 'user_name'
            }
        ),
        validators=[
            validators.validate_username,
            validators.contains_spaces,
        ]
    )
    passwd = forms.CharField(
        label='password',
        max_length=PASSWD_MAX_LEN,
        min_length=PASSWD_MIN_LEN,
        required=True,
        widget=forms.PasswordInput(
            attrs={
                'name': 'passwd',
                'id': 'passwd'
            }
        ),
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


class Login2FA(forms.Form):
    token_double_auth = forms.CharField(
        label='token de telegram',
        max_length=LEN_TOKEN2FA,
        min_length=LEN_TOKEN2FA,
        required=True,
        widget=forms.PasswordInput(
            attrs={
                'name': 'token_double_auth',
                'id': 'token_double_auth'
            }
        ),
        validators=[
            validators.token_2FA,
            validators.contains_spaces,
        ]
    )
    captcha = ReCaptchaField(
        widget=ReCaptchaV2Checkbox
    )


class LoginAdomGlobal(forms.Form):
    user_name = forms.CharField(
        label='Username', max_length=15, min_length=4, required=True, widget=forms.TextInput(attrs={'name': 'user_name', 'id': 'user_name'}))
    passwd = forms.CharField(label='Password', max_length=15,
                             min_length=4, required=True, widget=forms.PasswordInput(attrs={'name': 'passwd', 'id': 'passwd'}))
    token_double_auth = forms.CharField(
        label='Token Telegram', min_length=24, max_length=24, widget=forms.PasswordInput(attrs={'name': 'token_double_auth', 'id': 'token_double_auth'}))


class LoginSysadmin(AuthenticationForm):
    nickname = forms.CharField(
        label='Nickname', max_length=15, min_length=4, required=True, widget=forms.TextInput(attrs={'name': 'nickname', 'id': 'nickname'}))
    password = forms.CharField(label='Password', max_length=15,
                               min_length=4, required=True, widget=forms.PasswordInput(attrs={'name': 'password', 'id': 'password'}))
    token_double_auth = forms.CharField(
        label='Token de su bot de Telegram', min_length=24, max_length=24, widget=forms.PasswordInput(attrs={'name': 'token_double_auth', 'id': 'token_double_auth'}))


class SinginAdmin(forms.ModelForm):
    confirm_password = forms.CharField(label='Contraseña de confirmación', widget=forms.PasswordInput(
        attrs={
            'class': 'form-control',
            'placeholder': 'Ingrese de nuevo la contraseña',
            'id': 'repeat_password',
            'required': 'required',
        }
    ))

    class Meta:
        model = Sysadmin
        fields = ('nickname', 'chat_id', 'token_bot', 'password')
        label = {
            'nickname': 'nombre admin',
            'password': 'Contraseña del servidor', 
            'chat_id': 'chat id de telegram',
            'token_bot': 'token bot de telegram',
        }
        widgets = {
            'nickname': forms.TextInput(
                attrs={
                    'class': 'form-control',
                    'placeholder': 'Nickname del SysAdmin',
                }
            ),
            'password': forms.PasswordInput(
                attrs={
                    'class': 'form-control',
                    'placeholder': 'Contraseña del sysadmin',
                }
            ),
            'chat_id': forms.TextInput(
                attrs={
                    'class': 'form-control',
                    'placeholder': 'Chat ID de telegram',
                }
            ),
            'token_bot': forms.TextInput(
                attrs={
                    'class': 'form-control',
                    'placeholder': 'Token bot de telegram',
                }
            ),
        }
        # Verificación de contraseña (10char,uppercase,lowecase,digits,special)

    def clean(self):
        cleaned_data = super().clean()
        nickname = self.cleaned_data['nickname']
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        chat_id = self.cleaned_data['chat_id']
        token_bot = self.cleaned_data['token_bot']

        try:
            exist = Sysadmin.objects.filter(nickname__iexact=nickname).exists()
            if exist:
                raise forms.ValidationError("Este nickname ya existe")
            if nickname == '':
                raise forms.ValidationError('El Nickname no puede estar vacio')
            if len(nickname) < 4:
                raise forms.ValidationError(
                    'El Nickname debe contener al menos 4 caracteres')
        except ValidationError as e:
            self.add_error('nickname', e)

        try:
            if ' ' in password:
                raise forms.ValidationError(
                    'La "Contraseña" no debe contener espacios')
            if len(password) < 10:
                raise forms.ValidationError(
                    'La "Contraseña" debe contener al menos 10 caracteres')
            if not any(caracter.isupper() for caracter in password):
                raise forms.ValidationError(
                    'La "Contraseña" al menos debe contener una letra mayúscula')
            if not any(caracter.islower() for caracter in password):
                raise forms.ValidationError(
                    'La "Contraseña" al menos debe contener una letra minúscula')
            if not any(caracter.isdigit() for caracter in password):
                raise forms.ValidationError(
                    'La "Contraseña" al menos debe contener un número')
            if password == '':
                raise forms.ValidationError(
                    'La Contraseña no puede estar vacia')

            if password and confirm_password and password != confirm_password:
                self.add_error('confirm_password',
                               "Las contraseñas no coinciden.")
            if confirm_password == '':
                raise ValidationError(
                    'Repetir la contraseña no puede estar vacio')
        except ValidationError as e:
            self.add_error('password', e)

        try:
            exist = Sysadmin.objects.filter(chat_id__iexact=chat_id).exists()
            if exist:
                raise forms.ValidationError("Este Chat ID ya existe")
            if chat_id == '':
                raise forms.ValidationError('El Chat ID no puede estar vacio')
            if len(chat_id) < 10:
                raise forms.ValidationError(
                    'Su Chat ID no puede tener menos de 10 caracteres')
        except ValidationError as e:
            self.add_error('chat_id', e)

        try:
            exist = Sysadmin.objects.filter(
                token_bot__iexact=token_bot).exists()
            if exist:
                raise forms.ValidationError("Este Token BOT ya existe")
            if token_bot == '':
                raise forms.ValidationError(
                    'El Token de su BOT no puede estar vacio')
            if len(token_bot) < 46:
                raise forms.ValidationError(
                    'Su Token BOT no puede tener menos de 46 caracteres')
        except ValidationError as e:
            self.add_error('token_bot', e)

        return cleaned_data


class SinginServer(forms.ModelForm):
    confirm_password = forms.CharField(label='Contraseña de confirmación', widget=forms.PasswordInput(
        attrs={
            'class': 'form-control',
            'placeholder': 'Ingrese de nuevo la contraseña',
            'id': 'repeat_password',
            'required': 'required',
        }
    ))

    class Meta:
        model = Servidor
        fields = ('ipv4_address', 'sysadmin', 'password')
        label = {
            'ipv4_address': 'IP del servidor',
            'password': 'Contraseña del servidor',
            'sysadmin': 'Administrador del servidor',
        }
        widgets = {
            'ipv4_address': forms.TextInput(
                attrs={
                    'class': 'form-control',
                    'placeholder': 'IP del nuevo servidor',
                }
            ),
            'password': forms.PasswordInput(
                attrs={
                    'class': 'form-control',
                    'placeholder': 'Contraseña del servidor',
                }
            ),
            'sysadmin': forms.Select(
                attrs={
                    'class': 'form-control',
                    'placeholder': 'Administrador a monitorear',
                }
            ),
        }

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        try:
            if ' ' in password:
                raise forms.ValidationError(
                    'La "Contraseña" no debe contener espacios')
            if len(password) < 10:
                raise forms.ValidationError(
                    'La "Contraseña" debe contener al menos 10 caracteres')
            if not any(caracter.isupper() for caracter in password):
                raise forms.ValidationError(
                    'La "Contraseña" al menos debe contener una letra mayúscula')
            if not any(caracter.islower() for caracter in password):
                raise forms.ValidationError(
                    'La "Contraseña" al menos debe contener una letra minúscula')
            if not any(caracter.isdigit() for caracter in password):
                raise forms.ValidationError(
                    'La "Contraseña" al menos debe contener un número')
            if password == '':
                raise forms.ValidationError(
                    'La Contraseña no puede estar vacia')
            if password and confirm_password and password != confirm_password:
                self.add_error('confirm_password',
                               "Las contraseñas no coinciden.")
            if confirm_password == '':
                raise ValidationError(
                    'Repetir la contraseña no puede estar vacio')
        except ValidationError as e:
            self.add_error('password', e)
        return cleaned_data
