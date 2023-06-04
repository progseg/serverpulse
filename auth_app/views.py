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
# Create your views here.


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


def check_token_double_auth_lifecicle_admonglobal(object_nickname: str, form_token_double_auth: str) -> bool:
    timestamp_now = datetime.now(timezone.utc)

    try:
        object_admon_global = models.AdmonGlobal.objects.get(
            nickname=object_nickname)

    except:
        return False

    object_token_double_auth = object_admon_global.token_double_auth
    object_timestamp_token_double_auth = object_admon_global.timestamp_token_double_auth

    if (object_token_double_auth == form_token_double_auth and
            ((timestamp_now - object_timestamp_token_double_auth).total_seconds()) < 300.0):
        return True
    else:
        return False


def create_token_doble_auth_admonglobal(object_nickname: str) -> str:
    new_token_double_auth = ''.join(secrets.choice(
        string.ascii_letters + string.digits) for _ in range(8))
    try:
        models.AdmonGlobal.objects.filter(nickname=object_nickname).update(
            token_double_auth=new_token_double_auth, timestamp_token_double_auth=datetime.now())
        return new_token_double_auth
    except:
        return None


def send_token_double_auth_admonglobal(chat_id: str, token_bot: str, new_token_double_auth: str, nickname: str) -> bool:
    url = f'https://api.telegram.org/bot{token_bot}/sendMessage?chat_id={chat_id}&parse_mode=Markdown&text={new_token_double_auth}'

    response = requests.post(url)

    if response.status_code == 200:
        try:
            models.AdmonGlobal.objects.filter(nickname=nickname).update(
                token_double_auth=new_token_double_auth, timestamp_token_double_auth=datetime.now())
            return True
        except models.AdmonGlobal.DoesNotExist:
            return False
    else:
        return False


def request_token_admon_global(request: HttpRequest) -> HttpResponse:
    if request.method == 'POST':
        if request.content_type == 'application/json':
            data = json.loads(request.body)

            nickname_request = data.get('nickname')

            try:
                object_admon_global = models.AdmonGlobal.objects.get(
                    nickname=nickname_request)
                chat_id = object_admon_global.chat_id
                token_bot = object_admon_global.token_bot
                token_double_auth = create_token_doble_auth_admonglobal(
                    object_admon_global.nickname)
                if token_double_auth:
                    token_sended = send_token_double_auth_admonglobal(
                        chat_id, token_bot, token_double_auth, object_admon_global.nickname)
                else:
                    messages.error(
                        request, 'Ocurrió un error inesperado en su solicitud, inténtelo de nuevo')
                    return redirect('login_admon_global')

                if token_sended is True:
                    messages.success(
                        request, 'El token de doble autenticación fue mandado con éxito')
                    return redirect('login_admon_global')
                else:
                    messages.Error(
                        request, 'Ocurrió un error inesperado en su solicitud, inténtelo de nuevo')
                    return redirect('login_admon_global')
            except models.AdmonGlobal.DoesNotExist:
                messages.error(
                    request, 'Los datos proporcionados son incorrectos, vuelva a intentarlo')
                return redirect('login_admon_global')
        else:
            return HttpResponseBadRequest('Formato de solicitud incorrecto')
    else:
        return HttpResponseNotAllowed(['POST'])


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

            form_nickname = form_login_admon_global.cleaned_data['nickname']
            form_password = form_login_admon_global.cleaned_data['password']
            form_token_double_auth = form_login_admon_global.cleaned_data[
                'token_double_auth']
            try:
                object_admon_global = models.AdmonGlobal.objects.get(
                    nickname=form_nickname,
                    password=form_password,
                    token_double_auth=form_token_double_auth)
                if (check_token_double_auth_lifecicle_admonglobal(
                        object_admon_global.nickname,
                        form_token_double_auth)
                        is True):
                    if (object_admon_global.nickname == form_nickname
                            and object_admon_global.password == form_password
                            and object_admon_global.token_double_auth == form_token_double_auth
                            and object_admon_global.autorize_account == True):
                        return render(request, 'dashboard.html')
                    else:
                        messages.error(
                            request, 'Las crenciales proporcionadas no son válidas')
                        return redirect('login_admon_global')
                else:
                    messages.error(
                        request, 'El tiempo de vida del token ha caducado, por favor, genere uno nuevo')
                    return redirect('login_admon_global')
            except models.AdmonGlobal.DoesNotExist:
                messages.error(
                    request, 'Los datos proporcionados son incorrectos, vuelva a intentaelo')
                return redirect('login_admon_global')

        else:
            messages.error(
                request, 'Los datos proporcionados son incorrectos, vuelva a intentarlo')
            return redirect('login_admon_global')
    else:
        return HttpResponseBadRequest('Formato de solicitud incorrecto')


def check_token_double_auth_lifecicle_sysadmin(object_nickname: str, form_token_double_auth: str) -> bool:
    timestamp_now = datetime.now(timezone.utc)

    try:
        object_sysadmin = models.Sysadmin.objects.get(
            nickname=object_nickname)

    except:
        return False

    object_token_double_auth = object_sysadmin.token_double_auth
    object_timestamp_token_double_auth = object_sysadmin.timestamp_token_double_auth

    if (object_token_double_auth == form_token_double_auth and
            ((timestamp_now - object_timestamp_token_double_auth).total_seconds()) < 300.0):
        return True
    else:
        return False


def create_token_doble_auth_sysadmin(object_nickname: str) -> str:
    new_token_double_auth = ''.join(secrets.choice(
        string.ascii_letters + string.digits) for _ in range(8))
    try:
        models.Sysadmin.objects.filter(nickname=object_nickname).update(
            token_double_auth=new_token_double_auth, timestamp_token_double_auth=datetime.now())
        return new_token_double_auth
    except:
        return None


def send_token_double_auth_sysadmin(chat_id: str, token_bot: str, new_token_double_auth: str, nickname: str) -> bool:
    url = f'https://api.telegram.org/bot{token_bot}/sendMessage?chat_id={chat_id}&parse_mode=Markdown&text={new_token_double_auth}'

    response = requests.post(url)

    if response.status_code == 200:
        try:
            models.Sysadmin.objects.filter(nickname=nickname).update(
                token_double_auth=new_token_double_auth, timestamp_token_double_auth=datetime.now())
            return True
        except models.Sysadmin.DoesNotExist:
            return False
    else:
        return False


def request_token_sysadmin(request: HttpRequest) -> HttpResponse:
    if request.method == 'POST':
        if request.content_type == 'application/json':
            data = json.loads(request.body)

            nickname_request = data.get('nickname')

            try:
                object_sysadmin = models.Sysadmin.objects.get(
                    nickname=nickname_request)
                chat_id = object_sysadmin.chat_id
                token_bot = object_sysadmin.token_bot
                token_double_auth = create_token_doble_auth_sysadmin(
                    object_sysadmin.nickname)
                if token_double_auth:
                    token_sended = send_token_double_auth_sysadmin(
                        chat_id, token_bot, token_double_auth, object_sysadmin.nickname)
                else:
                    messages.error(
                        request, 'Ocurrió un error inesperado en su solicitud, inténtelo de nuevo')
                    return redirect('login_sysadmin')

                if token_sended is True:
                    messages.success(
                        request, 'El token de doble autenticación fue mandado con éxito')
                    return redirect('login_sysadmin')
                else:
                    messages.Error(
                        request, 'Ocurrió un error inesperado en su solicitud, inténtelo de nuevo')
                    return redirect('login_sysadmin')
            except models.Sysadmin.DoesNotExist:
                messages.error(
                    request, 'Los datos proporcionados son incorrectos, vuelva a intentarlo')
                return redirect('login_sysadmin')
        else:
            return HttpResponseBadRequest('Formato de solicitud incorrecto')
    else:
        return HttpResponseNotAllowed(['POST'])


def login_sysadmin(request: HttpRequest) -> HttpResponse:
    if request.method == 'GET':
        form_login_sysadmin = forms.LoginSysadmin()

        context = {
            'form': form_login_sysadmin
        }
        return render(request, 'login_sysadmin.html', context)

    elif request.method == 'POST':
        form_login_sysadmin = forms.LoginSysadmin(request.POST)
        print(form_login_sysadmin)
        if form_login_sysadmin.is_valid():

            form_nickname = form_login_sysadmin.cleaned_data['nickname']
            form_password = form_login_sysadmin.cleaned_data['password']
            form_token_double_auth = form_login_sysadmin.cleaned_data['token_double_auth']

            print(f'{form_nickname} {form_password} {form_token_double_auth}')
            try:
                object_sysadmin = models.Sysadmin.objects.get(
                    nickname=form_nickname,
                    password=form_password,
                    token_double_auth=form_token_double_auth)
                if (check_token_double_auth_lifecicle_sysadmin(
                        object_sysadmin.nickname,
                        form_token_double_auth)
                        is True):
                    if (object_sysadmin.nickname == form_nickname
                            and object_sysadmin.password == form_password
                            and object_sysadmin.token_double_auth == form_token_double_auth
                            and object_sysadmin.autorize_account == True):
                        return render(request, 'dashboard.html')
                    else:
                        messages.error(
                            request, 'Las crenciales proporcionadas no son válidas')
                        return redirect('login_sysadmin')
                else:
                    messages.error(
                        request, 'El tiempo de vida del token ha caducado, por favor, genere uno nuevo')
                    return redirect('login_sysadmin')
            except models.Sysadmin.DoesNotExist:
                messages.error(
                    request, 'Los datos proporcionados son incorrectos, vuelva a intentaelo')
                return redirect('login_sysadmin')
        else:
            messages.error(
                request, 'Los datos proporcionados son incorrectos, vuelva a intentarlo')
            return redirect('login_sysadmin')
    else:
        return HttpResponseBadRequest('Formato de solicitud incorrecto')
