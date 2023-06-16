from django.db import IntegrityError
from django.shortcuts import get_object_or_404, redirect, render
import logging
from django.http import HttpResponse, HttpRequest, HttpResponseNotAllowed
from django.urls import reverse_lazy
from . import decorators_admon_global
from django.views.decorators.csrf import csrf_protect
from auth_app import models
from . import forms
from django.views.generic import ListView, UpdateView, CreateView, DeleteView
from django.utils.html import escape
from django.contrib import messages
import bcrypt


# Create your views here.
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO,
                    filename='resgistroInicioAG.log', filemode='a')



def clean_specials(clean_data):
    escaped_data = {}
    for field_name, field_value in clean_data.items():
        escaped_data[field_name] = escape(field_value)
    return escaped_data


def gen_salt():
    salt = bcrypt.gensalt()
    return salt.decode()


def derivate_passwd(salt, passwd):
    salt_bytes = salt.encode()
    passwd_bytes = passwd.encode()

    try:
        hashed_passwd = bcrypt.hashpw(passwd_bytes, salt_bytes)
        return hashed_passwd.decode()
    except Exception as e:
        raise e


@decorators_admon_global.logged_global_required
@csrf_protect
def dashboard_admon_global(request: HttpRequest) -> HttpResponse:
    logging.info(
        'dashboard Admin Global: Se hace petición por el método: ' + request.method)
    if request.method == 'GET':
        return render(request, 'dashboard.html')
    else:
        return HttpResponseNotAllowed[('GET')]


class ListarAdministrador(ListView):
    model = models.Sysadmin
    template_name = 'listar_admin.html'
    context_object_name = 'admins'
    queryset = models.Sysadmin.objects.all()


def update_sysadmin(request, uuid):
    sysadmin = get_object_or_404(models.Sysadmin, uuid=uuid)

    if request.method == 'GET':
        form = forms.UpdateSysadmin(instance=sysadmin)

        form.fields['user_name'].initial = sysadmin.user_name
        form.fields['chat_id'].initial = sysadmin.chat_id
        form.fields['token_bot'].initial = sysadmin.token_bot

        context = {
            'form': form,
            'uuid': uuid,
            'sysadmin': sysadmin
        }
        return render(request, 'editar_admin.html', context)
    
    if request.method == 'POST':
        form = forms.UpdateSysadmin(request.POST, instance=sysadmin)
        if form.is_valid():

            cleaned_data = form.cleaned_data
            cleaned_data = clean_specials(cleaned_data)

            if cleaned_data.get('passwd'):
                new_salt = gen_salt()
                try:
                    hashed_passwd = derivate_passwd(new_salt, cleaned_data['passwd'])
                except Exception as e:
                    messages.error(request, f'Error: {e}')
                    return redirect('editar_admin')
                salt = sysadmin.salt
                salt.salt_value = new_salt
                salt.save()

                sysadmin.passwd = hashed_passwd
            if cleaned_data.get('user_name'):
                sysadmin.user_name = cleaned_data.get('user_name')

            if cleaned_data.get('chat_id'):
                sysadmin.chat_id = cleaned_data.get('chat_id')

            if cleaned_data.get('token_bot'):
                sysadmin.token_bot = cleaned_data.get('token_bot')
            
            try:
                sysadmin.save()
                messages.success(request, f'{sysadmin.user_name} actualizado')
                return redirect('listar_admin')
            except IntegrityError:
                messages.error(request, 'El nombre de usuario, Chat ID o token de bot ya existen')
                return redirect('editar_admin', uuid=uuid)

                
        else:
            context = {
                'uuid': uuid,
                'sysadmin': sysadmin,
                'form': form
            }
            return render(request, 'editar_admin.html', context)
    else:
        return HttpResponseNotAllowed(['GET', 'POST'])


def crear_administrador(request):
    if request.method == 'GET':
        form = forms.SinginAdmin()
        context = {
            'form': form
        }
        return render(request, 'crear_admin.html', context)
    elif request.method == 'POST':
        form = forms.SinginAdmin(request.POST)
        if form.is_valid():
            cleaned_data = form.cleaned_data
            cleaned_data = clean_specials(cleaned_data)

            salt = gen_salt()
            try:
                hashed_passwd = derivate_passwd(salt, cleaned_data['passwd'])
            except Exception as e:
                messages.error(request, f'Error: {e}')
                return redirect('crear_admin')

            new_salt = models.Salt(
                salt_value = salt
            )
            new_salt.save()

            new_sysadmin = models.Sysadmin(
                user_name=cleaned_data['user_name'],
                passwd = hashed_passwd,
                chat_id = cleaned_data['chat_id'],
                token_bot = cleaned_data['token_bot'],
                salt = new_salt
            )
            try:
                new_sysadmin.save()
                messages.success(request, 'El sysadmin se registró con éxito')
                return redirect('listar_admin')
            except IntegrityError:
                messages.error(request, 'El nombre de usuario, el Chat ID o el token de bot ya existen')
                return redirect('crear_admin')

        else:
            context = {
                'form': form
            }
            return render(request, 'crear_admin.html', context)
    else:
        return HttpResponseNotAllowed(['GET', 'POST'])


class EliminarAdministrador(DeleteView):
    model = models.Sysadmin
    template_name = 'eliminar_admin.html'
    success_url = reverse_lazy('listar_admin')
    slug_field = 'uuid'
    slug_url_kwarg = 'uuid'


def crear_server(request):
    if request.method == 'GET':
        form = forms.SinginServer()
        sysadmins = models.Sysadmin.objects.all()

        if not sysadmins:
            messages.error(request, 'Antes de registrar un servidor, debe crear un sysadmin')
            return redirect('listar_server')

        context = {
            'form': form,
            'sysadmins': sysadmins
        }

        return render(request, 'crear_server.html', context)
    
    elif request.method == 'POST':
        form = forms.SinginServer(request.POST)
        if form.is_valid():

            cleaned_data = form.cleaned_data
            cleaned_data = clean_specials(cleaned_data)

            salt = gen_salt()
            try:
                hashed_passwd = derivate_passwd(salt, cleaned_data['passwd'])
            except Exception as e:
                messages.error(request, f'Error: {e}')
                return redirect('crear_admin')

            new_salt = models.Salt(
                salt_value = salt
            )
            new_salt.save()

            sysadmin_uuid = cleaned_data['sysadmin']
            sysadmin_instance = get_object_or_404(models.Sysadmin, uuid = sysadmin_uuid)

            new_server = models.Servidor(
                ipv4_address=cleaned_data['ipv4_address'],
                passwd = hashed_passwd,
                sysadmin = sysadmin_instance,
                salt = new_salt
            )

            try:
                new_server.save()
                messages.success(request, 'El servidor ha sido registrado con éxito')
                return redirect('listar_server')
            except  IntegrityError:
                messages.error(request, 'El nombre de usuario, el Chat ID o el token de bot ya existen')
                return redirect('crear_server')
        else:
            sysadmins = models.Sysadmin.objects.all()

            if not sysadmins:
                messages.error(request, 'Antes de registrar un servidor, debe crear un sysadmin')
                return redirect('listar_server')
            context = {
                'form': form,
                'sysadmins': sysadmins
            }
            return render(request, 'crear_server.html', context)
    else:
        return HttpResponseNotAllowed(['GET', 'POST'])


class ListarServidor(ListView):
    model = models.Servidor
    template_name = 'listar_server.html'
    context_object_name = 'servers'
    queryset = models.Servidor.objects.all()


def update_servidor(request, uuid):
    servidor = get_object_or_404(models.Servidor, uuid=uuid)
    
    if request.method == 'GET':
        form = forms.UpdateServer(instance=servidor)

        form.fields['ipv4_address'].initial = servidor.ipv4_address

        context = {
            'form': form,
            'uuid': uuid,
            'servidor': servidor
        }
        return render(request, 'editar_server.html', context)
    
    if request.method == 'POST':
        form = forms.UpdateServer(request.POST, instance=servidor)
        if form.is_valid():

            cleaned_data = form.cleaned_data
            cleaned_data = clean_specials(cleaned_data)

            if cleaned_data.get('passwd'):
                new_salt = gen_salt()
                try:
                    hashed_passwd = derivate_passwd(new_salt, cleaned_data['passwd'])
                except Exception as e:
                    messages.error(request, f'Error: {e}')
                    return redirect('crear_server')
                salt = servidor.salt
                salt.salt_value = new_salt
                servidor.passwd = hashed_passwd
                salt.save()

            if cleaned_data.get('ipv4_address'):
                servidor.ipv4_address = cleaned_data.get('ipv4_address')

            try:
                servidor.save()
                messages.success(request, f'{servidor.ipv4_address} actualizado')
                return redirect('listar_server')
            except IntegrityError:
                messages.error(request, 'La dirección IPv4 ya está en uso')
                return redirect('editar_server', uuid=uuid)
        else:
            context = {
                'uuid': uuid,
                'servidor': servidor,
                'form': form
            }
            return render(request, 'editar_server.html', context)
    else:
        return HttpResponseNotAllowed(['GET', 'POST'])


class EliminarServidor(DeleteView):
    model = models.Servidor
    template_name = 'eliminar_server.html'
    success_url = reverse_lazy('listar_server')
    slug_field = 'uuid'
    slug_url_kwarg = 'uuid'


def change_relation(request, uuid):
    servidor = get_object_or_404(models.Servidor, uuid=uuid)
    sysadmins = models.Sysadmin.objects.all()

    if request.method == 'GET':
        form = forms.RelationSysadminServer(instance=servidor)

        context = {
            'form': form,
            'sysadmins': sysadmins
        }
        return render(request, 'editar_relacion.html', context)
    
    elif request.method == 'POST':
        form = forms.RelationSysadminServer(request.POST, instance=servidor)

        if form.is_valid():
            form.save()
            messages.success(request, 'Relación actualizada')
            return redirect('listar_server')
        else:
            context= {
                'form': form,
                'uuid': uuid
            }
            return render(request, 'editar_relacion.html', context)
    else:
        return HttpResponseNotAllowed(['GET', 'POST'])

