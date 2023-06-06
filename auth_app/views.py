from django.shortcuts import render, redirect
from django.urls import reverse
from django.http import HttpRequest, HttpResponse
from django.http.response import HttpResponseNotAllowed, HttpResponseBadRequest
from django.contrib import messages
import secrets
from datetime import datetime, timezone
import string
from . import forms
from . import models
import json
import requests
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponseBadRequest, HttpResponseNotAllowed, JsonResponse
from admon_global import views as views_admon_global
# Create your views here.

TOKENOTP_LIVE = 180.0  # 3 min
MAX_ATTEMPS = 5
MIN_ATTEMPS = 0
LOCK_TIME_RANGE = 300.0  # 5 min


def singin(request: HttpRequest) -> HttpResponse:

    if request.method == 'GET':
        form_singin = forms.Singin()

        context = {
            'form': form_singin
        }
        return render(request, 'singin.html', context)

    elif request.method == 'POST':
        form_singin = forms.Singin(request.POST)
        if form_singin.is_valid():
            nickname = form_singin.cleaned_data['nickname']
            password = form_singin.cleaned_data['password']
            chat_id = form_singin.cleaned_data['chat_id']
            token_bot = form_singin.cleaned_data['token_bot']

            Sysadmin = models.Sysadmin()

            Sysadmin.nickname = nickname
            Sysadmin.password = password
            Sysadmin.chat_id = chat_id
            Sysadmin.token_bot = token_bot

            Sysadmin.token_double_auth = ''.join(secrets.choice(
                string.ascii_letters + string.digits) for _ in range(8))
            Sysadmin.timestamp_ultimo_intento = datetime.now()
            Sysadmin.timestamp_token_double_auth = datetime.now()
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0]
            else:
                ip = request.META.get('REMOTE_ADDR')
            Sysadmin.ipv4_address = ip

            try:
                Sysadmin.save()

                messages.success(
                    request, f'El usuario {nickname} fue registrado con éxito')
                return redirect('login_sys_admin')
            except:
                messages.error(
                    request, 'Ocurrió un error inesperado en el servidor')
                return redirect('singin')
        else:
            messages.error(request, 'Los datos proporcionados no son válidos')
            return redirect('singin')
    else:
        return HttpResponseNotAllowed(['GET', 'POST'])


# Section of login admon global

# Section of token OTP admon global
def request_token_admon_global(request: HttpRequest) -> HttpResponse:
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])

    if request.content_type != 'application/json':
        return HttpResponseBadRequest('Formato de solicitud incorrecto')

    data = json.loads(request.body)
    form_user_name = data.get('user_name')
    try:
        models.AdmonGlobal.objects.get(user_name=form_user_name)
    except:
        print('Nombre de usario no encontrado')
        message = 'El usuario no fue encontrado.\nIngrese correctamente su nombre de usuario en el campo username'
        return JsonResponse({'message': message, 'message_type': 'error'})

    new_token_double_auth = create_tokenotp_admon_global()
    if new_token_double_auth is None:
        message = 'La solicitud no se pudo completar y el token no fue creado, inténtelo de nuevo'
        return JsonResponse({'message': message, 'message_type': 'error'})

    token_updated = update_tokenotp_admon_global(
        form_user_name, new_token_double_auth)

    if token_updated is not True:
        message = 'Ocurrio un fallo inesperado al registrar su token, solicite un nuevo token'
        return JsonResponse({'message': message, 'message_type': 'error'})

    token_sended = send_tokenotp_admon_global(form_user_name)
    if token_sended is not True:
        message = 'Ocurrió un fallo inesperado al enviar el token, solicite un nuevo token'
        return JsonResponse({'message': message, 'message_type': 'error'})

    message = 'El token fue enviado con éxito, revise su telegram'
    return JsonResponse({'message': message, 'message_type': 'success'})


def create_tokenotp_admon_global() -> str:
    new_token_double_auth = ''.join(secrets.choice(
        string.ascii_letters + string.digits) for _ in range(24))
    return new_token_double_auth


def update_tokenotp_admon_global(object_user_name: str, new_token_double_auth: str) -> bool:
    try:
        models.AdmonGlobal.objects.filter(user_name=object_user_name).update(
            token_double_auth=new_token_double_auth)
        return True
    except:
        return False


def send_tokenotp_admon_global(admon_global_user_name: str) -> bool:
    try:
        admon_global = models.AdmonGlobal.objects.get(
            user_name=admon_global_user_name)
        token_bot = admon_global.token_bot
        chat_id = admon_global.chat_id
        token_double_auth = admon_global.token_double_auth
    except:
        return False

    try:
        url = f'https://api.telegram.org/bot{token_bot}/sendMessage?chat_id={chat_id}&parse_mode=Markdown&text={token_double_auth}'
        response = requests.post(url)
        if response.status_code == 200:
            admon_global.timestamp_token_double_auth = datetime.now(
                timezone.utc)
            admon_global.save()
            return True
    except:
        admon_global.timestamp_token_double_auth = None
        admon_global.token_double_auth = None
        admon_global.save()
        return False


# Section of token OTP validations: it's check the token correspond to user and the token does not expired
def check_tokenotp_valid_admon_global(object_user_name: str, form_token_double_auth: str) -> bool:
    try:
        object_admon_global = models.AdmonGlobal.objects.get(
            user_name=object_user_name)
    except:
        return False

    object_token_double_auth = object_admon_global.token_double_auth
    object_timestamp_token_double_auth = object_admon_global.timestamp_token_double_auth
    timestamp_now = datetime.now(timezone.utc)

    if (object_token_double_auth == form_token_double_auth
            and ((timestamp_now
                  - object_timestamp_token_double_auth).total_seconds())
            < TOKENOTP_LIVE):
        return True
    else:
        return False


# login attemps validation over IPv4
def get_ip_client(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')

    return ip


def save_ip_client(ip: str, user_name: str) -> bool:
    timestamp_now = datetime.now(timezone.utc)
    try:
        admon_global = models.AdmonGlobal.objects.get(user_name=user_name)
        if admon_global.ipv4_address != ip:
            admon_global.ipv4_address = ip
            admon_global.timestamp_ultimo_intento = timestamp_now
            admon_global.intentos = MIN_ATTEMPS
            admon_global.save()
        return True
    except:
        return False


def check_attemps_login(attemps_account: int) -> bool:
    if (attemps_account < MAX_ATTEMPS):
        return True
    else:
        return False


def increment_attemps_account(object_admon_global: models.AdmonGlobal) -> bool:
    # incrementa el contador de intentos y actualiza el timestamp
    try:
        update_attemps = object_admon_global.intentos + 1
        object_admon_global.intentos = update_attemps
        object_admon_global.save()
        return True
    except:
        return False


def block_admon_global(object_admon_global: models.AdmonGlobal) -> bool:
    # si ya pasaron más de 5 minutos, reinicia el contador y el timestamp, sino, truena la atenticación
    # False seugnifica que la cuenta no se bloquea, True que la cuenta si se bloquea
    timestamp_now = datetime.now(timezone.utc)
    timestamp_attemps = object_admon_global.timestamp_ultimo_intento

    # if it is a new client
    if timestamp_attemps is None:
        object_admon_global.timestamp_ultimo_intento = timestamp_now
        object_admon_global.intentos = MIN_ATTEMPS
        object_admon_global.save()
        return False

    if (((timestamp_now
          - timestamp_attemps).total_seconds())
            < LOCK_TIME_RANGE):
        object_admon_global.timestamp_ultimo_intento = timestamp_now
        object_admon_global.save()
        return True
    else:
        object_admon_global.intentos = MIN_ATTEMPS
        object_admon_global.timestamp_ultimo_intento = None
        object_admon_global.save()
        return False


def restart_attemps(object_admon_global: models.AdmonGlobal) -> bool:
    # settea el contador a 0 y borra el último timestamp de intentos
    try:
        object_admon_global.intentos = MIN_ATTEMPS
        object_admon_global.timestamp_ultimo_intento = None
        object_admon_global.save()
        return True
    except:
        return False


def delete_ipv4_client(object_admon_global: models.AdmonGlobal) -> bool:
    try:
        object_admon_global.ipv4_address = None
        object_admon_global.save()
        return True
    except:
        return False


# Section of login admon global
def login_admon_global(request: HttpRequest) -> HttpResponse:
    if request.method == 'GET':
        form_login_admon_global = forms.LoginAdomGlobal()

        context = {
            'form': form_login_admon_global
        }

        return render(request, 'login_admon_global.html', context)

    elif request.method == 'POST':
        form_login_admon_global = forms.LoginAdomGlobal(request.POST)

        if form_login_admon_global.is_valid():

            form_user_name = form_login_admon_global.cleaned_data['user_name']
            form_passwd = form_login_admon_global.cleaned_data['passwd']
            form_token_double_auth = form_login_admon_global.cleaned_data[
                'token_double_auth']

            ip = get_ip_client(request)
            if save_ip_client(ip, form_user_name) is not True:
                messages.error(
                    request, 'Ocurrió un error inesperado, no se pudo guardar la dirección IPv4 del cliente')
                return redirect('login_admon_global')

            try:
                object_admon_global = models.AdmonGlobal.objects.get(
                    user_name=form_user_name)
            except:
                messages.error(request, 'Cuenta no encontrada')

            attemps = object_admon_global.intentos
            if check_attemps_login(attemps) is not True:
                if block_admon_global(object_admon_global) is True:
                    messages.error(
                        request, 'Intentos de inicio de sesión superados, espere 5 minutos antes de intentar de nuevo')
                    return redirect('login_admon_global')

            # Basic auth username and password
            if (object_admon_global.user_name == form_user_name and
                    object_admon_global.passwd == form_passwd):
                admon_global_authenticated = True
            else:
                object_admon_global.token_double_auth = None
                object_admon_global.save()
                admon_global_authenticated = False

            if admon_global_authenticated is not True:
                if increment_attemps_account(object_admon_global) is not True:
                    messages.error(
                        request, 'Error al actualizar los intentos de inicio de sesión')
                    return (request, 'login_admon_global')
                messages.error(
                    request, 'Las credenciales proporcionadas no son válidas, inténtelo de nuevo')
                return redirect('login_admon_global')

            double_auth_status = login_double_auth_admon_global(
                form_user_name, form_token_double_auth)

            if double_auth_status is not True:
                if increment_attemps_account(object_admon_global) is not True:
                    messages.error(
                        request, 'Error al actualizar los intentos de inicio de sesión')
                    return (request, 'login_admon_global')
                # change token to it be single use even when athentication is successfully
                new_otptoken = create_tokenotp_admon_global()

                if new_otptoken is None:
                    messages.error(
                        request, 'Ocurrió un error inesperado en el servidor, su sesión no se creará. Inténtelo de nuevo')
                    return redirect('login_admon_global')

                token_updated = update_tokenotp_admon_global(
                    form_user_name, new_otptoken)

                if token_updated is not True:
                    messages.error(
                        request, 'Ocurrió un error inesperado en el servidor, su sesión no se creará. Inténtelo de nuevo')
                    return redirect('login_admon_global')

                messages.error(
                    request, 'El token no es correcto o a expirado, solicite un nuevo token')
                return redirect('login_admon_global')

            # Session start
            restart_attemps(object_admon_global)
            delete_ipv4_client(object_admon_global)
            request.session['logged'] = True
            return redirect('dashboard_admon_global')
        else:
            messages.error(
                request, 'Los datos proporcionados no contienen un formato válido, vuelva a intentarlo')
            return redirect('login_admon_global')
    else:
        return HttpResponseNotAllowed(['GET', 'POST'])


def login_double_auth_admon_global(form_user_name: str, form_token_double_auth: str) -> bool:
    token_alive = check_tokenotp_valid_admon_global(
        form_user_name, form_token_double_auth)

    # token is wrong, OTP token changes to be single use
    if token_alive is not True:
        new_otptoken = create_tokenotp_admon_global()

        if new_otptoken is None:
            return False

        token_updated = update_tokenotp_admon_global(
            form_user_name, new_otptoken)

        if token_updated is not True:
            return False

        return False

    # auth is ok
    return True


def logout(request: HttpRequest) -> HttpResponse:
    request.session['logged'] = False
    request.session.flush()
    return redirect('login_sys_admin')


# Section of login SysAdmin

def login_sys_admin(request: HttpRequest) -> HttpResponse:
    if request.method == 'GET':
        form_login_sys_admin = forms.LoginSysadmin()

        context = {
            'form': form_login_sys_admin
        }

        return render(request, 'login_sys_admin.html', context)

    elif request.method == 'POST':
        form_login_sys_admin = forms.LoginSysadmin(request.POST)
        if form_login_sys_admin.is_valid():

            form_nickname = form_login_sys_admin.cleaned_data['nickname']
            form_password = form_login_sys_admin.cleaned_data['password']
            form_token_double_auth = form_login_sys_admin.cleaned_data[
                'token_double_auth']

            ip = get_ip_client(request)
            if save_ip_client_sysadmin(ip, form_nickname) is not True:
                messages.error(
                    request, 'Ocurrió un error inesperado, no se pudo guardar la dirección IPv4 del cliente')
                return redirect('login_sys_admin')

            try:
                object_sys_admin = models.Sysadmin.objects.get(
                    nickname=form_nickname)
            except:
                messages.error(request, 'Cuenta no encontrada')

            attemps = object_sys_admin.intentos
            if check_attemps_login(attemps) is not True:
                if block_sys_admin(object_sys_admin) is True:
                    messages.error(
                        request, 'Intentos de inicio de sesión superados, espere 5 minutos antes de intentar de nuevo')
                    return redirect('login_sys_admin')

            # Basic auth username and password
            if (object_sys_admin.nickname == form_nickname and
                    object_sys_admin.password == form_password):
                sys_admin_authenticated = True
            else:
                object_sys_admin.token_double_auth = None
                object_sys_admin.save()
                sys_admin_authenticated = False

            if sys_admin_authenticated is not True:
                if increment_attemps_account_sysadmin(object_sys_admin) is not True:
                    messages.error(
                        request, 'Error al actualizar los intentos de inicio de sesión')
                    return (request, 'login_sys_admin')
                messages.error(
                    request, 'Las credenciales proporcionadas no son válidas, inténtelo de nuevo')
                return redirect('login_sys_admin')

            double_auth_status = login_double_auth_sys_admin(
                form_nickname, form_token_double_auth)

            if double_auth_status is not True:
                if increment_attemps_account_sysadmin(object_sys_admin) is not True:
                    messages.error(
                        request, 'Error al actualizar los intentos de inicio de sesión')
                    return (request, 'login_sys_admin')
                # change token to it be single use even when athentication is successfully
                new_otptoken = create_tokenotp_sys_admin()

                if new_otptoken is None:
                    messages.error(
                        request, 'Ocurrió un error inesperado en el servidor, su sesión no se creará. Inténtelo de nuevo')
                    return redirect('login_sys_admin')

                token_updated = update_tokenotp_sys_admin(
                    form_nickname, new_otptoken)

                if token_updated is not True:
                    messages.error(
                        request, 'Ocurrió un error inesperado en el servidor, su sesión no se creará. Inténtelo de nuevo')
                    return redirect('login_sys_admin')

                messages.error(
                    request, 'El token no es correcto o a expirado, solicite un nuevo token')
                return redirect('login_sys_admin')

            # Session start
            restart_attemps_sysadmin(object_sys_admin)
            delete_ipv4_client_sysadmin(object_sys_admin)
            request.session['logged'] = True
            return redirect('dashboard_sys_admin')
        else:
            messages.error(
                request, 'Los datos proporcionados no contienen un formato válido, vuelva a intentarlo')
            return redirect('login_sys_admin')
    else:
        return HttpResponseNotAllowed(['GET', 'POST'])


def login_double_auth_sys_admin(form_nickname: str, form_token_double_auth: str) -> bool:
    token_alive = check_tokenotp_live_sys_admin(
        form_nickname, form_token_double_auth)

    # token is wrong, OTP token changes to be single use
    if token_alive is not True:
        new_otptoken = create_tokenotp_sys_admin()

        if new_otptoken is None:
            return False

        token_updated = update_tokenotp_sys_admin(
            form_nickname, new_otptoken)

        if token_updated is not True:
            return False

        return False

    # auth is ok
    return True


def logout_sys_admin(request: HttpRequest) -> HttpResponse:
    request.session['logged'] = False
    request.session.flush()
    return redirect('login_sys_admin')


# Section of login admon global

# Section of token OTP admon global

def request_token_sys_admin(request: HttpRequest) -> HttpResponse:
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])

    if request.content_type != 'application/json':
        return HttpResponseBadRequest('Formato de solicitud incorrecto')

    data = json.loads(request.body)
    form_nickname = data.get('nickname')
    try:
        models.Sysadmin.objects.get(nickname=form_nickname)
    except:
        print('Nombre de usario no encontrado')
        message = 'El usuario no fue encontrado.\nIngrese correctamente su nombre de usuario en el campo nickname'
        return JsonResponse({'message': message, 'message_type': 'error'})

    new_token_double_auth = create_tokenotp_sys_admin()
    if new_token_double_auth is None:
        message = 'La solicitud no se pudo completar y el token no fue creado, inténtelo de nuevo'
        return JsonResponse({'message': message, 'message_type': 'error'})

    token_updated = update_tokenotp_sys_admin(
        form_nickname, new_token_double_auth)

    if token_updated is not True:
        message = 'Ocurrio un fallo inesperado al registrar su token, solicite un nuevo token'
        return JsonResponse({'message': message, 'message_type': 'error'})

    token_sended = send_tokenotp_sys_admin(form_nickname)
    if token_sended is not True:
        message = 'Ocurrió un fallo inesperado al enviar el token, solicite un nuevo token'
        return JsonResponse({'message': message, 'message_type': 'error'})

    message = 'El token fue enviado con éxito, revise su telegram'
    return JsonResponse({'message': message, 'message_type': 'success'})


def create_tokenotp_sys_admin() -> str:
    new_token_double_auth = ''.join(secrets.choice(
        string.ascii_letters + string.digits) for _ in range(24))
    return new_token_double_auth


def update_tokenotp_sys_admin(object_nickname: str, new_token_double_auth: str) -> bool:
    try:
        models.Sysadmin.objects.filter(nickaname=object_nickname).update(
            token_double_auth=new_token_double_auth, timestamp_token_double_auth=datetime.now(timezone.utc))
        return True
    except:
        return False


def send_tokenotp_sys_admin(sys_admin_nickname: str) -> bool:
    try:
        sys_admin = models.Sysadmin.objects.get(
            nickname=sys_admin_nickname)
        token_bot = sys_admin.token_bot
        chat_id = sys_admin.chat_id
        token_double_auth = sys_admin.token_double_auth
    except:
        return False

    try:
        url = f'https://api.telegram.org/bot{token_bot}/sendMessage?chat_id={chat_id}&parse_mode=Markdown&text={token_double_auth}'
        response = requests.post(url)
        if response.status_code == 200:
            sys_admin.timestamp_token_double_auth = datetime.now(
                timezone.utc)
            sys_admin.save()
            return True
    except:
        sys_admin.timestamp_token_double_auth = None
        sys_admin.token_double_auth = None
        sys_admin.save()
        return False


def check_tokenotp_live_sys_admin(object_nickname: str, form_token_double_auth: str) -> bool:
    try:
        object_sys_admin = models.Sysadmin.objects.get(
            user_name=object_nickname)

    except:
        return False

    object_token_double_auth = object_sys_admin.token_double_auth
    object_timestamp_token_double_auth = object_sys_admin.timestamp_token_double_auth
    timestamp_now = datetime.now(timezone.utc)

    if (object_token_double_auth == form_token_double_auth
            and ((timestamp_now
                  - object_timestamp_token_double_auth).total_seconds())
            < TOKENOTP_LIVE):
        return True
    else:
        return False
    
def save_ip_client_sysadmin(ip: str, nickname: str) -> bool:
    timestamp_now = datetime.now(timezone.utc)
    try:
        sys_admin = models.Sysadmin.objects.get(nickname=nickname)
        if sys_admin.ipv4_address != ip:
            sys_admin.ipv4_address = ip
            sys_admin.timestamp_ultimo_intento = timestamp_now
            sys_admin.intentos = MIN_ATTEMPS
            sys_admin.save()
        return True
    except:
        return False
    

def increment_attemps_account_sysadmin(object_sys_admin: models.Sysadmin) -> bool:
    # incrementa el contador de intentos y actualiza el timestamp
    try:
        update_attemps = object_sys_admin.intentos + 1
        object_sys_admin.intentos = update_attemps
        object_sys_admin.save()
        return True
    except:
        return False


def block_sys_admin(object_sys_admin: models.Sysadmin) -> bool:
    # si ya pasaron más de 5 minutos, reinicia el contador y el timestamp, sino, truena la atenticación
    # False seugnifica que la cuenta no se bloquea, True que la cuenta si se bloquea
    timestamp_now = datetime.now(timezone.utc)
    timestamp_attemps = object_sys_admin.timestamp_ultimo_intento

    # if it is a new client
    if timestamp_attemps is None:
        object_sys_admin.timestamp_ultimo_intento = timestamp_now
        object_sys_admin.intentos = MIN_ATTEMPS
        object_sys_admin.save()
        return False

    if (((timestamp_now
          - timestamp_attemps).total_seconds())
            < LOCK_TIME_RANGE):
        object_sys_admin.timestamp_ultimo_intento = timestamp_now
        object_sys_admin.save()
        return True
    else:
        object_sys_admin.intentos = MIN_ATTEMPS
        object_sys_admin.timestamp_ultimo_intento = None
        object_sys_admin.save()
        return False
    

def restart_attemps_sysadmin(object_sys_admin: models.Sysadmin) -> bool:
    # settea el contador a 0 y borra el último timestamp de intentos
    try:
        object_sys_admin.intentos = MIN_ATTEMPS
        object_sys_admin.timestamp_ultimo_intento = None
        object_sys_admin.save()
        return True
    except:
        return False


def delete_ipv4_client_sysadmin(object_sys_admin: models.Sysadmin) -> bool:
    try:
        object_sys_admin.ipv4_address = None
        object_sys_admin.save()
        return True
    except:
        return False