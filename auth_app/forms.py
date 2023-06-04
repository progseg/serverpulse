from django import forms
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
