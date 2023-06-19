from django.core.exceptions import ValidationError
import re


# min,max 10 char for chatid
# min,max 46 char for token_bot
# min 12, max 24 char for passwd
# min 4, max 20 char for username


# common validators
def contains_spaces(value):
    """
    Valida si el valor contiene espacios en blanco.

    Args:
    - value: El valor a validar.

    Excepciones:
    - ValidationError: Se genera si el valor contiene 
    espacios en blanco.
    """
    if re.search(r' ', value):
        raise ValidationError('El campo no puede contener espacios en blanco')


# username validators
def validate_username(value):
    """
    Valida el formato del nombre de usuario.

    Args:
    - value: El valor a validar.

    Excepciones:
    - ValidationError: Se genera si el valor no cumple 
    con el formato de nombre de usuario válido.
    """
    if not re.match(r'^[a-zA-Z0-9_]+$', value):
        raise ValidationError(
            'El campo solo puede contener letras minúsculas, mayúsculas números y guiones bajos.')


# password validators
def contains_uppercase(value):
    """
    Valida si la contraseña contiene al menos una letra mayúscula.

    Args:
    - value: La contraseña a validar.

    Excepciones:
    - ValidationError: Se genera si la contraseña no contiene 
    al menos una letra mayúscula.
    """
    if not any(char.isupper() for char in value):
        raise ValidationError(
            "La contraseña debe contener al menos una letra mayúscula.")


def contains_lowecase(value):
    """
    Valida si la contraseña contiene al menos una letra minúscula.

    Args:
    - value: La contraseña a validar.

    Excepciones:
    - ValidationError: Se genera si la contraseña no contiene 
    al menos una letra minúscula.
    """
    if not any(char.islower() for char in value):
        raise ValidationError(
            "La contraseña debe contener al menos una letra minúscula.")


def contains_digits(value):
    """
    Valida si la contraseña contiene al menos un número.

    Args:
    - value: La contraseña a validar.

    Excepciones:
    - ValidationError: Se genera si la contraseña no 
    contiene al menos un número.
    """
    if not any(char.isdigit() for char in value):
        raise ValidationError(
            "La contraseña debe contener al menos un número.")


def contais_special(value):
    """
    Valida si la contraseña contiene al menos un carácter especial.

    Args:
    - value: La contraseña a validar.

    Excepciones:
    - ValidationError: Se genera si la contraseña no contiene al menos un carácter especial.
    """
    if not any(not char.isalnum() for char in value):
        raise ValidationError(
            "La contraseña debe contener al menos un carácter especial.")


# telegram bot_token validators
def telegram_bot_token(value):
    """
    Valida el formato del token de bot de Telegram.

    Args:
    - value: El valor a validar.

    Excepciones:
    - ValidationError: Se genera si el formato del 
    token de bot de Telegram no es válido.
    """
    pattern = r'^\d+:[A-Za-z0-9_-]+$'
    if not re.match(pattern, value):
        raise ValidationError(
            'El formato del token de bot de Telegram no es válido.')


# telegram chatid validators
def only_digits(value):
    """
    Valida si el chatid contiene solo dígitos.

    Args:
    - value: El valor a validar.

    Excepciones:
    - ValidationError: Se genera si el chatid no contiene solo dígitos.
    """
    if not value.isdigit():
        raise ValidationError('El chatid no contiene el formato correcto')

# token 2FA validator


def token_2FA(value):
    """
    Valida el formato del token de doble autenticación.

    Args:
    - value: El valor a validar.

    Excepciones:
    - ValidationError: Se genera si el formato del token 
    de doble autenticación no es válido.
    """
    pattern = r'^[A-Za-z0-9]+$'
    if not re.match(pattern, value):
        raise ValidationError(
            'El formato del token de doble autenticación no es válido.')
