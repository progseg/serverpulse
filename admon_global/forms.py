from django import forms
from auth_app.validators import *
from auth_app.models import Servidor, Sysadmin

USERNAME_MAX_LEN = 20
USERNAME_MIN_LEN = 4

PASSWD_MAX_LEN = 24
PASSWD_MIN_LEN = 12

LEN_TOKEN_BOT = 46
LEN_CHATID = 10

LEN_TOKEN2FA = 24

class SinginAdmin(forms.ModelForm):
    confirm_password = forms.CharField(
        label='Contraseña de confirmación',
        widget=forms.PasswordInput(
            attrs={
                'class': 'form-control',
                'placeholder': 'Ingrese de nuevo la contraseña',
                'id': 'repeat_password',
                'required': 'required',
            }
        ),
        min_length=PASSWD_MIN_LEN,
        max_length=PASSWD_MAX_LEN,
        validators=[
            contains_digits,
            contains_lowecase,
            contains_uppercase,
            contais_special,
            contains_spaces
        ]
    )

    class Meta:
        model = Sysadmin
        fields = ('user_name', 'chat_id', 'token_bot', 'passwd')
        label = {
            'user_name': 'nombre admin',
            'passwd': 'Contraseña del servidor',
            'chat_id': 'chat id de telegram',
            'token_bot': 'token bot de telegram',
        }
        widgets = {
            'user_name': forms.TextInput(
                attrs={
                    'class': 'form-control',
                    'placeholder': 'user_name del SysAdmin',
                }
            ),
            'passwd': forms.PasswordInput(
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
        },
        # Verificación de contraseña (10char,uppercase,lowecase,digits,special)


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
        # Verificación de contraseña (10char,uppercase,lowecase,digits,special)