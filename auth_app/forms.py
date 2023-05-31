from django import forms


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
    nickname = forms.CharField(
        label='nombre único de usuario', max_length=15, min_length=4, required=True)
    password = forms.CharField(label='password', max_length=15,
                               min_length=4, required=True, widget=forms.PasswordInput)
    token_double_auth = forms.CharField(
        label='token_double_auth', min_length=8, max_length=8)


class LoginSysadmin(forms.Form):
    nickname = forms.CharField(
        label='nombre único de usuario', max_length=15, min_length=4, required=True)
    password = forms.CharField(label='password', max_length=15,
                               min_length=4, required=True, widget=forms.PasswordInput)
    token_double_auth = forms.CharField(
        label='token_doble_auth', min_length=8, max_length=8)
