from django.core.exceptions import ValidationError
import re


# min,max 10 char for chatid
# min,max 46 char for token_bot
# min 12, max 24 char for passwd
# min 4, max 20 char for username


# common validators
def contains_spaces(value):
    if ' ' in value:
        raise ValidationError('El campo no puede contener espacios en blanco')


# username validators
def validate_username(value):
    if not re.match(r'^[a-zA-Z0-9_]+$', value):
        raise ValidationError(
            'El campo solo puede contener letras minúsculas, mayúsculas números y guiones bajos.')


# password validators
def contains_uppercase(value):
    if not any(char.isupper() for char in value):
        raise ValidationError(
            "La contraseña debe contener al menos una letra mayúscula.")


def contains_lowecase(value):
    if not any(char.islower() for char in value):
        raise ValidationError(
            "La contraseña debe contener al menos una letra minúscula.")


def contains_digits(value):
    if not any(char.isdigit() for char in value):
        raise ValidationError(
            "La contraseña debe contener al menos un número.")


def contais_special(value):
    if not any(not char.isalnum() for char in value):
        raise ValidationError(
            "La contraseña debe contener al menos un carácter especial.")


# telegram bot_token validators
def telegram_bot_token(value):
    pattern = r'^\d+:[A-Za-z0-9_-]+$'
    if not re.match(pattern, value):
        raise ValidationError(
            'El formato del token de bot de Telegram no es válido.')


# telegram chatid validators
def only_digits(value):
    if not value.isdigit():
        raise ValidationError('El chatid no contiene el formato correcto')

# token 2FA validator


def token_2FA(value):
    pattern = r'^[A-Za-z0-9]+$'
    if not re.match(pattern, value):
        raise ValidationError(
            'El formato del token de doble autenticación no es válido.')
