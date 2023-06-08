from typing import Any, Dict
from django import forms
from .models import *
from . import views
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm


class Singin(forms.Form):
    nickname = forms.CharField(
        label='nombre único de usuario', max_length=15, min_length=4, required=True)
    password = forms.CharField(label='contraseña', max_length=15,
                               min_length=4, required=True, widget=forms.PasswordInput)
    repeat_password = forms.CharField(
        label='Repetir contraseña', max_length=15, min_length=4, required=True, widget=forms.PasswordInput)
    chat_id = forms.CharField(label='ID de su chat con su bot en Telegram',
                              min_length=10, max_length=10, required=True)
    token_bot = forms.CharField(
        label='token de su bot en Telegram', min_length=40, max_length=50, required=True)

    def clean_nickname(self):
        nickname = self.cleaned_data['nickname']
        exist = Sysadmin.objects.filter(nickname__iexact=nickname).exists()
        if exist:
            raise forms.ValidationError("Este nickname ya existe")
        if nickname == '':
            raise forms.ValidationError('El Nickname no puede estar vacio')
        if len(nickname) < 4:
            raise forms.ValidationError(
                'El Nickname debe contener al menos 4 caracteres')
        return nickname

    # Verificación de contraseña (10char,uppercase,lowecase,digits,special)
    def clean_password(self):
        password = self.cleaned_data['password']
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
            raise forms.ValidationError('La Contraseña no puede estar vacia')
        return password

    # Verificacion de si la contraeña coincide
    def clean_repeat_password(self):
        password = self.cleaned_data['password']
        repeat_password = self.cleaned_data['repeat_password']
        if password != repeat_password:
            # Este es el error que esta en forms.error
            raise forms.ValidationError('Las contraseñas no coinciden')
        if repeat_password == '':
            raise forms.ValidationError(
                'Repetir la contraseña no puede estar vacio')
        return repeat_password
    

    def save(self, commit=True):
        user = super().save(commit=False) # Se redefine la forma en que se guarda la contraseña
        password_hash = views.hashear_password(self.cleaned_data['password'])
        user.password = password_hash
        if commit:
            user.save()
        return user


    def clean_chat_id(self):
        chat_id = self.cleaned_data['chat_id']
        exist = Sysadmin.objects.filter(chat_id__iexact=chat_id).exists()
        if exist:
            raise forms.ValidationError("Este Chat ID ya existe")
        if chat_id == '':
            raise forms.ValidationError('El Chat ID no puede estar vacio')
        if len(chat_id) < 10:
            raise forms.ValidationError(
                'Su Chat ID no puede tener menos de 10 caracteres')
        return chat_id

    def clean_token_bot(self):
        token_bot = self.cleaned_data['token_bot']
        exist = Sysadmin.objects.filter(token_bot__iexact=token_bot).exists()
        if exist:
            raise forms.ValidationError("Este Token BOT ya existe")
        if token_bot == '':
            raise forms.ValidationError(
                'El Token de su BOT no puede estar vacio')
        if len(token_bot) < 46:
            raise forms.ValidationError(
                'Su Token BOT no puede tener menos de 46 caracteres')
        return token_bot


class LoginAdomGlobal(forms.Form):
    user_name = forms.CharField(
        label='username', max_length=15, min_length=4, required=True, widget=forms.TextInput(attrs={'name': 'user_name', 'id': 'user_name'}))
    passwd = forms.CharField(label='password', max_length=15,
                             min_length=4, required=True, widget=forms.PasswordInput(attrs={'name': 'passwd', 'id': 'passwd'}))
    token_double_auth = forms.CharField(
        label='token telegram', min_length=24, max_length=24, widget=forms.PasswordInput(attrs={'name': 'token_double_auth', 'id': 'token_double_auth'}))


class LoginSysadmin(AuthenticationForm):
    nickname = forms.CharField(
        label='nombre único de usuario', max_length=15, min_length=4, required=True)
    password = forms.CharField(label='password', max_length=15,
                               min_length=4, required=True, widget=forms.PasswordInput)
    token_double_auth = forms.CharField(
        label='token_doble_auth', min_length=8, max_length=8)
