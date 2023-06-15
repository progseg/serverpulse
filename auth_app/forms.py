import re
from typing import Any, Dict
from django import forms
from .models import *
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