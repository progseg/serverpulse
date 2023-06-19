from django.shortcuts import render, redirect
from django.http import HttpRequest, HttpResponse
from django.http.response import HttpResponseNotAllowed
from django.contrib import messages
import secrets
from datetime import timezone
import string
from . import forms
from . import models
from django.db.models import Model
import requests
import logging
from admon_global import decorators_admon_global as dec_admong
from sysadmin import decorators_sys_admin as dec_sysadmin
from django.views.decorators.csrf import csrf_protect
from django.utils import timezone
import bcrypt
from django.utils.html import escape
from . import decorators
from django.views.decorators.cache import never_cache
# Create your views here.


logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO,
                    filename='resgistros.log', filemode='a')

TOKENOTP_LIVE = 180.0  # 3 min
MAX_ATTEMPS = 5
MIN_ATTEMPS = 0
LOCK_TIME_RANGE = 300.0  # 5 min

# General functions

# Section of token OTP


def clean_specials(clean_data):
    """
    Limpia los datos especiales escapando los valores de los campos.

    Args:
        clean_data (dict): Diccionario con los datos a limpiar.

    Returns:
        dict: Diccionario con los datos escapados.
    """
    escaped_data = {}
    for field_name, field_value in clean_data.items():
        escaped_data[field_name] = escape(field_value)
    return escaped_data


def derivate_passwd(salt, passwd):
    """
    Deriva la contraseña utilizando una sal y el algoritmo bcrypt.

    Args:
        salt (str): Sal utilizada en la derivación.
        passwd (str): Contraseña a derivar.

    Returns:
        str: Contraseña derivada.
    Raises:
        Exception: Si ocurre un error durante la derivación 
        de la contraseña.
    """
    salt_bytes = salt.encode()
    passwd_bytes = passwd.encode()

    try:
        hashed_passwd = bcrypt.hashpw(passwd_bytes, salt_bytes)
        return hashed_passwd.decode()
    except Exception as e:
        raise e


def request_tokenotp(user: Model) -> bool:
    """
    Realiza una solicitud de token OTP para el usuario.

    Args:
        user (Model): Instancia del modelo de usuario.

    Returns:
        bool: True si la solicitud de token fue exitosa, 
        False en caso contrario.
    """
    logging.info(
        'mandar token: Se hace petición de token')

    new_token_double_auth = create_tokenotp()
    if new_token_double_auth is None:
        logging.error(
            'mandar token: El token no se creo')
        return False

    token_updated = update_tokenotp(
        user, new_token_double_auth)

    if token_updated is not True:
        logging.error(
            'mandar token: El token no se registro adecuadamente')
        return False

    token_sended = send_tokenotp(user, new_token_double_auth)
    if token_sended is not True:
        logging.error(
            'mandar token: El token no se mando adecuadamente')
        return False

    logging.info(
        'mandar token: El token se mando adecuadamente')
    return True


def create_tokenotp() -> str:
    """
    Crea un nuevo token OTP.

    Returns:
        str: Token OTP generado.
    """
    new_token_double_auth = ''.join(secrets.choice(
        string.ascii_letters + string.digits) for _ in range(24))
    return new_token_double_auth


def update_tokenotp(user: Model, new_token_double_auth: str) -> bool:
    """
    Actualiza el token OTP del usuario en la base de datos.

    Args:
        user (Model): Instancia del modelo de usuario.
        new_token_double_auth (str): Nuevo token OTP.

    Returns:
        bool: True si la actualización fue exitosa, 
        False en caso contrario.
    """
    try:
        user.__class__.objects.filter(uuid=user.uuid).update(
            token_double_auth = new_token_double_auth,
        )
    except:
        logging.error(
            f'No se pudo actualizar el token en la base de datos: {e}')
        return False
    
    if new_token_double_auth is None:
        try:
            user.__class__.objects.filter(uuid=user.uuid).update(
                timestamp_token_double_auth = None,
            )
            return True
        except Exception as e:
            logging.error(
                f'No se pudo actualizar el token en la base de datos: {e}')
            return False
    return True


def send_tokenotp(user: Model, new_token_double_auth) -> bool:
    """
    Envía un token OTP al usuario a través de Telegram.

    Args:
        user (Model): El usuario al que se enviará el token.
        new_token_double_auth: El nuevo token de autenticación 
        de doble factor.

    Returns:
        bool: True si se envió el token correctamente, 
        False en caso contrario.
    """

    username = user.user_name
    token_bot = user.token_bot
    chat_id = user.chat_id
    token_double_auth = new_token_double_auth

    try:
        url = f'https://api.telegram.org/bot{token_bot}/sendMessage?chat_id={chat_id}&parse_mode=Markdown&text={token_double_auth}'
        response = requests.post(url)
    except Exception as e:
        logging.error(
            f'El mensaje a telegram para {username} no se completó: {e}')
        user.__class__.objects.filter(uuid=user.uuid).update(
            timestamp_token_double_auth = None,
            token_double_auth = None
        )
        return False

    if response.status_code == 200:
        user.__class__.objects.filter(uuid=user.uuid).update(
            timestamp_token_double_auth = timezone.now()
        )
        return True
    else:
        logging.error(
            f'El mensaje a telegram para {username} no se completó: {response.status_code}')
        user.__class__.objects.filter(uuid=user.uuid).update(
            timestamp_token_double_auth = None,
            token_double_auth = None
        )
        return False


def check_tokenotp_valid(user: Model, form_tokenotp: str) -> bool:
    """
    Verifica si el token OTP proporcionado por el usuario es válido.

    Args:
        user (Model): El usuario para el cual se verifica el token.
        form_tokenotp (str): El token OTP proporcionado por el usuario.

    Returns:
        bool: True si el token es válido, False en caso contrario.
    """

    user_token = user.token_double_auth
    user_timestamp_token = user.timestamp_token_double_auth
    timestamp_now = timezone.now()

    if (user_token == form_tokenotp
            and ((timestamp_now
                  - user_timestamp_token).total_seconds())
            < TOKENOTP_LIVE):
        return True
    else:
        return False


# login attemps validation over IPv4
def get_ip_client(request: HttpRequest) -> str:
    """
    Obtiene la dirección IP del cliente que realiza la solicitud.

    Args:
        request (HttpRequest): La solicitud HTTP recibida.

    Returns:
        str: La dirección IP del cliente.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')

    return ip


def save_ip_client(user: Model, ip: str) -> bool:
    """
    Guarda la dirección IP del cliente en el objeto de usuario 
    proporcionado.

    Args:
        user (Model): El usuario para el cual se guarda 
        la dirección IP.
        ip (str): La dirección IP del cliente.

    Returns:
        bool: True si se guarda la dirección IP correctamente, 
        False en caso contrario.
    """

    timestamp_now = timezone.now()

    if user.ipv4_address != ip:
        user.__class__.objects.filter(uuid=user.uuid).update(
            ipv4_address = ip,
            timestamp_ultimo_intento = timestamp_now,
            intentos = MIN_ATTEMPS
        )
        return True
    else:
        return True


def delete_ipv4_client(user: Model) -> bool:
    """
    Elimina la dirección IP almacenada del cliente en el 
    objeto de usuario proporcionado.

    Args:
        user (Model): El usuario para el cual se eliminará 
        la dirección IP.

    Returns:
        bool: True si se elimina la dirección IP correctamente, 
        False en caso contrario.
    """
    try:
        user.__class__.objects.filter(uuid=user.uuid).update(
            ipv4_address = None
        )
        return True
    except:
        return False


# Section of attempt count
def check_attemps_login(attemps_count: int) -> bool:
    """
    Verifica si el número de intentos de inicio de sesión 
    es menor que el máximo permitido.

    Args:
        attemps_count (int): El número de intentos de 
        inicio de sesión.

    Returns:
        bool: True si los intentos son menores que el 
        máximo permitido, False en caso contrario.
    """
    if (attemps_count < MAX_ATTEMPS):
        return True
    else:
        return False


def increment_attemps_account(user: Model) -> bool:
    """
    Incrementa el contador de intentos de inicio de sesión 
    y actualiza el timestamp.

    Args:
        user (Model): El usuario para el cual se incrementan 
        los intentos.

    Returns:
        bool: True si se incrementan los intentos correctamente, 
        False en caso contrario.
    """
    # incrementa el contador de intentos y actualiza el timestamp
    update_attemps = user.intentos + 1
    update_timestamp_attemps = timezone.now()

    try:
        user.__class__.objects.filter(uuid=user.uuid).update(
            intentos = update_attemps,
            timestamp_ultimo_intento = update_timestamp_attemps
        )
        return True
    except:
        return False


def block_user(user: Model) -> bool:
    """
    Bloquea la cuenta del usuario si el tiempo de bloqueo no ha expirado.

    Args:
        user (Model): El usuario para el cual se verifica el tiempo de bloqueo.

    Returns:
        bool: True si la cuenta está bloqueada, False si no está bloqueada.
    """
    # si ya pasaron más de 5 minutos, reinicia el contador y el timestamp, sino, truena la atenticación
    # False seugnifica que la cuenta no se bloquea, True que la cuenta si se bloquea
    timestamp_now = timezone.now()
    timestamp_last_attemp = user.timestamp_ultimo_intento

    # if user is a new client
    if timestamp_last_attemp is None:
        user.__class__.objects.filter(uuid=user.uuid).update(
                timestamp_ultimo_intento = timestamp_now,
                intentos = MIN_ATTEMPS
        )
        return False

    if (((timestamp_now
          - timestamp_last_attemp).total_seconds())
            < LOCK_TIME_RANGE):
        user.__class__.objects.filter(uuid=user.uuid).update(
            timestamp_ultimo_intento = timestamp_now
        )
        return True
    else:
        # if blocking time is over, attemps will be restart
        user.__class__.objects.filter(uuid=user.uuid).update(
            intentos = MIN_ATTEMPS,
            timestamp_ultimo_intento = None
        )
        return False


def restart_attemps(user: Model) -> bool:
    """
    Reinicia el contador de intentos de inicio de sesión 
    y el timestamp.

    Args:
        user (Model): El usuario para el cual se reinician 
        los intentos.

    Returns:
        bool: True si se reinician los intentos correctamente, 
        False en caso contrario.
    """
    try:
        user.__class__.objects.filter(uuid=user.uuid).update(
            intentos = MIN_ATTEMPS,
            timestamp_ultimo_intento = None
        )
        return True
    except:
        return False


# logout section
def logout(request: HttpRequest) -> HttpResponse:
    """
    Cierra la sesión del usuario actual en la vista 
    de administrador global.

    Args:
    - request: La solicitud HTTP recibida.

    Return:
    - HttpResponse: Redirige a la página de inicio de 
    sesión del administrador global.
    """
    logging.info(
        'logout Admin Global: Se hace petición por el método: ' + request.method)
    request.session.flush()
    return redirect('login_admon_global')


def logout_sysadmin(request: HttpRequest) -> HttpResponse:
    """
    Cierra la sesión del usuario actual en la vista 
    de sysadmin.

    Args:
    - request: La solicitud HTTP recibida.

    Return:
    - HttpResponse: Redirige a la página de inicio de 
    sesión del sysadmin.
    """
    logging.info(
        'logout sysadmin: Se hace petición por el método: ' + request.method)
    request.session.flush()
    return redirect('login_sysadmin')


# Section of login admon global
@never_cache
def login_admon_global(request: HttpRequest) -> HttpResponse:
    """
    Maneja la página de inicio de sesión del administrador global.

    Args:
    - request: La solicitud HTTP recibida.

    Return:
    - HttpResponse: Devuelve la página de inicio de sesión del 
    administrador global o redirige a la página de inicio de sesión 
    si el usuario ya ha iniciado sesión.
    """
    if request.method == 'GET':
        logging.info(
            'login Admin Global: Se hace petición por el método: ' + request.method)
        form_login = forms.Login()

        if request.session.get('logged') is True:
            username = request.session.get('username')

            try:
                user = models.AdmonGlobal.objects.get(
                    user_name=username)
            except:
                request.session.flush()
                logging.error('login Admin Global: Error no existe el usuario')
                messages.error(request, 'Cuenta no encontrada')
                return redirect('login_admon_global')

            new_token = None
            update_tokenotp(user, new_token)
            increment_attemps_account(user)

            request.session.flush()
            messages.info(request, 'Usted ha abandonado su sesión')
            return redirect('login_admon_global')

        context = {
            'form': form_login
        }

        return render(request, 'login.html', context)

    elif request.method == 'POST':
        form_login = forms.Login(request.POST)

        if form_login.is_valid():

            form_user_name = form_login.cleaned_data['user_name']
            form_passwd = form_login.cleaned_data['passwd']

            try:
                user = models.AdmonGlobal.objects.get(
                    user_name=form_user_name)
            except:
                logging.error('login Admin Global: Error no existe el usuario')
                messages.error(request, 'Cuenta no encontrada')
                return redirect('login_admon_global')

            ip = get_ip_client(request)
            if save_ip_client(user, ip) is not True:
                messages.error(
                    request, 'Ocurrió un error inesperado, no se pudo guardar la dirección IPv4 del cliente')
                logging.error(
                    'login Admin Global: Error al guardar la dirección IP del usuario')
                return redirect('login_admon_global')

            attemps = user.intentos
            if check_attemps_login(attemps) is not True:
                if block_user(user) is True:
                    messages.error(
                        request, 'Intentos de inicio de sesión superados, espere 5 minutos antes de intentar de nuevo')
                    logging.error(
                        'login Admin Global: Error se agotaron los intentos para iniciar sesión')
                    return redirect('login_admon_global')

            # Basic auth username and password

            salt = user.salt.salt_value

            passwd_hashed = derivate_passwd(salt, form_passwd)
            if (user.user_name == form_user_name and
                    user.passwd == passwd_hashed):
                user_authenticated = True
            else:
                # if user fails basic auth, token is cancel
                new_token = None
                update_tokenotp(user, new_token)
                user_authenticated = False

            if user_authenticated is not True:
                if increment_attemps_account(user) is not True:
                    messages.error(
                        request, 'Error al actualizar los intentos de inicio de sesión')

                    logging.error(
                        'login Admin Global: Error al momento de actualizar intentos al momento de iniciar sesión')

                    return redirect('login_admon_global')
                messages.error(
                    request, 'Las credenciales proporcionadas no son válidas, inténtelo de nuevo')

                logging.error(
                    'login Admin Global: Error al momento de ingresar las credenciales del usuario')

                return redirect('login_admon_global')

            # The basic auth is valid and token was sended correctly

            # Session start
            request.session['logged'] = True
            request.session['username'] = user.user_name
            request.session['token_spected'] = True

            logging.info(
                f'login admon global: Basic auth success to {user.user_name} from {user.ipv4_address}')
            return redirect('2FAadmonglobal')
        else:
            logging.error(
                f'login admin global: Basic auth incorrect')

            context = {
                'form': form_login
            }
            return render(request, 'login.html', context)
    else:
        return HttpResponseNotAllowed(['GET', 'POST'])


@decorators.logged_required
@csrf_protect
@never_cache
def login_double_auth_admon_global(request: HttpRequest) -> HttpResponse:
    """
    Maneja la página de inicio de sesión de autenticación doble del admin global.

    Args:
    - request: La solicitud HTTP recibida.

    Return:
    - HttpResponse: Devuelve la página de inicio de sesión de autenticación 
    doble del sysadmin o redirige a la página de inicio de sesión si el usuario 
    no ha completado la autenticación básica o la autenticación de dos factores.
    """
    if request.method == 'GET':

        if request.session.get('token_spected') is not True:
            username = request.session.get('username')

            try:
                user = models.AdmonGlobal.objects.get(
                    user_name=username)
            except:
                logging.error('login Admin Global: Error no existe el usuario')
                messages.error(request, 'Cuenta no encontrada')
                return redirect('login_admon_global')

            new_token = None
            update_tokenotp(user, new_token)
            increment_attemps_account(user)

            request.session.flush()
            messages.info(request, 'Usted ha abandonado su sesión')
            return redirect('login_admon_global')

        form_double_auth = forms.Login2FA()

        context = {
            'form': form_double_auth
        }

        username = request.session.get('username')

        try:
            user = models.AdmonGlobal.objects.get(
                user_name=username)
        except:
            request.session.flush()
            messages.error(request,
                           'Error inesperado. Vuelva a inicar sesión')
            return redirect('login_adom_global')

        if request_tokenotp(user) is not True:
            request.session.flush()
            new_token = None
            update_tokenotp(user, new_token)
            messages.error(request,
                           'No se completó la solicitud del token. Por favor, compruebe su información de 2FA con el webmaster')
            return redirect('login_admon_global')

        request.session['username'] = user.user_name
        request.session['token_spected'] = True

        return render(request, 'login2FA.html', context)

    elif request.method == 'POST':
        form_2FA = forms.Login2FA(request.POST)

        if form_2FA.is_valid():

            session_username = request.session.get('username')
            form_token = form_2FA.cleaned_data['token_double_auth']

            try:
                user = models.AdmonGlobal.objects.get(
                    user_name=session_username)
            except:
                request.session.flush()
                logging.error(
                    f'Credenciales no encontradas para {session_username}')
                messages.error(request,
                               'No se encontraron las credenciales proporcionadas')
                return redirect('login_admon_global')

            token_alive = check_tokenotp_valid(user, form_token)

            # if token is wrong, OTP token changes to be single use
            if token_alive is not True:

                new_token = None
                token_updated = update_tokenotp(user, new_token)
                if token_updated is not True:
                    messages.error(
                        request, 'Error interno, solicite un nuevo token')
                    return redirect('login_admon_global')

                increment_attemps_account(user)
                request.session.flush()
                messages.error(request,
                               'El token es inválido. Ha expirado o no es el correcto, solicite un nuevo token')
                return redirect('login_admon_global')

            new_token = None
            update_tokenotp(user, new_token)

            user.__class__.objects.filter(uuid=user.uuid).update(
                intentos = 0,
                timestamp_ultimo_intento = None,
                ipv4_address = None
            )
            request.session['token_spected'] = False
            request.session['role'] = 'global'
            return redirect('dashboard_admon_global')

        else:
            request.session['token_spected'] = False
            request.session.flush()
            messages.error(
                request, 'El desafío captcha no fue completado, se cancela el inicio de sesión')
            return redirect('login_admon_global')
    else:
        return HttpResponseNotAllowed(['GET', 'POST'])


# Section of Sysadmin
@never_cache
def login_sysadmin(request: HttpRequest) -> HttpResponse:
    """
    Maneja la página de inicio de sesión del sysadmin.

    Args:
    - request: La solicitud HTTP recibida.

    Return:
    - HttpResponse: Devuelve la página de inicio de sesión 
    del sysadmin o redirige a la página de inicio de sesión 
    si el usuario ya ha iniciado sesión.
    """
    if request.method == 'GET':
        logging.info(
            'login sysadmin: Se hace petición por el método: ' + request.method)
        form_login = forms.Login()

        if request.session.get('logged') is True:
            username = request.session.get('username')

            try:
                user = models.Sysadmin.objects.get(
                    user_name=username)
            except:
                request.session.flush()
                logging.error('login sysadmin: Error no existe el usuario')
                messages.error(request, 'Cuenta no encontrada')
                return redirect('login_sysadmin')

            new_token = None
            update_tokenotp(user, new_token)
            increment_attemps_account(user)

            request.session.flush()
            messages.info(request, 'Usted ha abandonado su sesión')
            return redirect('login_sysadmin')

        context = {
            'form': form_login
        }

        return render(request, 'login.html', context)

    elif request.method == 'POST':
        form_login = forms.Login(request.POST)

        if form_login.is_valid():

            form_user_name = form_login.cleaned_data['user_name']
            form_passwd = form_login.cleaned_data['passwd']

            try:
                user = models.Sysadmin.objects.get(
                    user_name=form_user_name)
            except:
                logging.error('login sysadmin: Error no existe el usuario')
                messages.error(request, 'Cuenta no encontrada')
                return redirect('login_sysadmin')

            ip = get_ip_client(request)
            if save_ip_client(user, ip) is not True:
                messages.error(
                    request, 'Ocurrió un error inesperado, no se pudo guardar la dirección IPv4 del cliente')
                logging.error(
                    'login sysadmin: Error al guardar la dirección IP del usuario')
                return redirect('login_sysadmin')

            attemps = user.intentos
            if check_attemps_login(attemps) is not True:
                if block_user(user) is True:
                    messages.error(
                        request, 'Intentos de inicio de sesión superados, espere 5 minutos antes de intentar de nuevo')
                    logging.error(
                        'login sysadmin: Error se agotaron los intentos para iniciar sesión')
                    return redirect('login_sysadmin')

            # Basic auth username and password
            salt = user.salt.salt_value
            passwd_hashed = derivate_passwd(salt, form_passwd)
            if (user.user_name == form_user_name and
                    user.passwd == passwd_hashed):
                user_authenticated = True
            else:
                # if user fails basic auth, token is cancel
                new_token = None
                update_tokenotp(user, new_token)
                user_authenticated = False

            if user_authenticated is not True:
                if increment_attemps_account(user) is not True:
                    messages.error(
                        request, 'Error al actualizar los intentos de inicio de sesión')

                    logging.error(
                        'login sysadmin: Error al momento de actualizar intentos al momento de iniciar sesión')

                    return redirect('login_sysadmin')
                messages.error(
                    request, 'Las credenciales proporcionadas no son válidas, inténtelo de nuevo')

                logging.error(
                    'login sysadmin: Error al momento de ingresar las credenciales del usuario')

                return redirect('login_sysadmin')

            # The basic auth is valid and token was sended correctly

            # Session start
            request.session['logged'] = True
            request.session['username'] = user.user_name
            request.session['token_spected'] = True

            logging.info(
                f'login admon global: Basic auth success to {user.user_name} from {user.ipv4_address}')
            return redirect('2FAsysadmin')
        else:
            logging.error(
                f'login admin global: Basic auth incorrect')

            context = {
                'form': form_login
            }
            return render(request, 'login.html', context)
    else:
        return HttpResponseNotAllowed(['GET', 'POST'])


@decorators.logged_required
@csrf_protect
@never_cache
def login_double_auth_sysadmin(request: HttpRequest) -> HttpResponse:
    """
    Maneja la página de inicio de sesión de autenticación doble del sysadmin.

    Args:
    - request: La solicitud HTTP recibida.

    Return:
    - HttpResponse: Devuelve la página de inicio de sesión de autenticación 
    doble del sysadmin o redirige a la página de inicio de sesión si el usuario 
    no ha completado la autenticación básica o la autenticación de dos factores.
    """
    if request.method == 'GET':

        if request.session.get('token_spected') is not True:
            username = request.session.get('username')

            try:
                user = models.Sysadmin.objects.get(
                    user_name=username)
            except:
                logging.error('login sysadmin: Error no existe el usuario')
                messages.error(request, 'Cuenta no encontrada')
                return redirect('login_sysadmin')

            new_token = None
            update_tokenotp(user, new_token)
            increment_attemps_account(user)

            request.session.flush()
            messages.info(request, 'Usted ha abandonado su sesión')
            return redirect('login_sysadmin')

        form_double_auth = forms.Login2FA()

        context = {
            'form': form_double_auth
        }

        username = request.session.get('username')

        try:
            user = models.Sysadmin.objects.get(
                user_name=username)
        except:
            request.session.flush()
            messages.error(request,
                           'Error inesperado. Vuelva a inicar sesión')
            return redirect('login_sysadmin')

        if request_tokenotp(user) is not True:
            request.session.flush()
            new_token = None
            update_tokenotp(user, new_token)
            messages.error(request,
                           'No se completó la solicitud del token. Por favor, compruebe su información 2FA con el admonGlobal')
            return redirect('login_sysadmin')

        request.session['username'] = user.user_name
        request.session['token_spected'] = True

        return render(request, 'login2FA.html', context)

    elif request.method == 'POST':
        form_2FA = forms.Login2FA(request.POST)

        if form_2FA.is_valid():

            session_username = request.session.get('username')
            form_token = form_2FA.cleaned_data['token_double_auth']

            try:
                user = models.Sysadmin.objects.get(
                    user_name=session_username)
            except:
                request.session.flush()
                logging.error(
                    f'Credenciales no encontradas para {session_username}')
                messages.error(request,
                               'No se encontraron las credenciales proporcionadas')
                return redirect('login_sysadmin')

            token_alive = check_tokenotp_valid(user, form_token)

            # if token is wrong, OTP token changes to be single use
            if token_alive is not True:

                new_token = None
                token_updated = update_tokenotp(user, new_token)
                if token_updated is not True:
                    messages.error(
                        request, 'Error interno, solicite un nuevo token')
                    return redirect('login_sysadmin')

                increment_attemps_account(user)
                request.session.flush()
                messages.error(request,
                               'El token es inválido. Ha expirado o no es el correcto, solicite un nuevo token')
                return redirect('login_sysadmin')

            new_token = None
            update_tokenotp(user, new_token)
            user.__class__.objects.filter(uuid=user.uuid).update(
                intentos = 0,
                timestamp_ultimo_intento = None,
                ipv4_address = None
            )
            uuid = str(user.uuid)
            request.session['token_spected'] = False
            request.session['role'] = 'sysadmin'
            request.session['uuid'] = uuid
            return redirect('dashboard_sys_admin')

        else:
            request.session['token_spected'] = False
            logout(request)
            messages.error(
                request, 'El desafío captcha no fue completado, se cancela el inicio de sesión')
            return redirect('login_sysadmin')
    else:
        return HttpResponseNotAllowed(['GET', 'POST'])

