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
from django.http import HttpResponseBadRequest, HttpResponseNotAllowed
# Create your views here.

TOKENOTP_LIVE = 180.0


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
                return redirect('login_sysadmin')
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

    new_token_double_auth = create_tokenotp_admon_global()
    if new_token_double_auth is None:
        messages.error(
            request, 'La solicitud no se pudo completar y el token no fue creado, inténtelo de nuevo')
        return redirect('login_admon_global')

    data = json.loads(request.body)
    form_user_name = data.get('user_name')
    token_updated = update_tokenotp_admon_global(
        form_user_name, new_token_double_auth)

    if token_updated is not True:
        messages.error(
            request, 'Ocurrio un fallo inesperado al registrar su token, solicite un nuevo token')
        return redirect('login_admon_global')

    token_sended = send_tokenotp_admon_global(form_user_name)
    if token_sended is True:
        messages.success(
            request, 'El token fue enviado con éxito, revise su chat de Telegram')
        return redirect('login_admon_global')
    else:
        messages.error(
            request, 'Ocurrió un fallo inesperado al enviar el token, solicite un nuevo token')
        return redirect('login_admon_global')


def create_tokenotp_admon_global() -> str:
    new_token_double_auth = ''.join(secrets.choice(
        string.ascii_letters + string.digits) for _ in range(24))
    return new_token_double_auth


def update_tokenotp_admon_global(object_user_name: str, new_token_double_auth: str) -> bool:
    try:
        models.AdmonGlobal.objects.filter(user_name=object_user_name).update(
            token_double_auth=new_token_double_auth, timestamp_token_double_auth=datetime.now(timezone.utc))
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
            return True
    except:
        return False


# Section of token OTP validations
def check_tokenotp_live_admon_global(object_user_name: str, form_token_double_auth: str) -> bool:
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

            token_alive = check_tokenotp_live_admon_global(
                form_user_name, form_token_double_auth)
            if token_alive is not True:
                messages.error(
                    request, 'El token de autenticación expiró, inténtelo de nuevo')
                return redirect('login_admon_global')

            admon_global_authenticated = models.AdmonGlobal.objects.get(
                user_name=form_user_name, passwd=form_passwd, token_double_auth=form_token_double_auth)
            if admon_global_authenticated is None:

                # nickname or password is wrong, OTP token changes to be single use
                new_otptoken = create_tokenotp_admon_global()

                if new_otptoken is None:
                    messages.error(
                        request, 'La solicitud no se pudo completar y el token no fue creado, inténtelo de nuevo')
                    return redirect('login_admon_global')

                token_updated = update_tokenotp_admon_global(
                    form_user_name, new_otptoken)

                if token_updated is not True:
                    messages.error(
                        request, 'Ocurrio un fallo inesperado al registrar su token, solicite un nuevo token')
                    return redirect('login_admon_global')

                messages.error(
                    request, "La autenticación falló, su token fue revocado. \
                        revise sus credenciales, solicite un nuevo token e intente iniciar sesión")
                return redirect('login_admon_global')

            else:

                new_token_session = secrets.token_hex(16)
                models.AdmonGlobal.objects.filter(user_name=form_user_name, passwd=form_passwd,
                                                  token_double_auth=form_token_double_auth).update(token_session=new_token_session)

                request.session['logged'] = True
                request.session['sessionid'] = admon_global_authenticated.token_session

                return redirect('dashboard_admon_global')
        else:
            messages.error(
                request, 'Los datos proporcionados no contienen un formato válido, vuelva a intentarlo')
            return redirect('login_admon_global')
    else:
        return HttpResponseNotAllowed(['GET', 'POST'])


def dashboard_admon_global(request: HttpRequest) -> HttpResponse:
    if request.method == 'GET':
        return render(request, 'dashboard.html')


def logout_admon_global(request: HttpRequest) -> HttpResponse:
    request.session['logged'] = False
    request.session.flush()
    return redirect('login_admon_global')
