from django.shortcuts import redirect, render
import logging
from django.http import HttpResponse, HttpRequest, HttpResponseNotAllowed
from django.urls import reverse_lazy
from . import decorators_admon_global
from django.views.decorators.csrf import csrf_protect
from auth_app import models
from . import forms
from django.views.generic import TemplateView, ListView, UpdateView, CreateView, DeleteView, FormView
from django.utils.html import escape
import hashlib
import secrets
import string
import binascii
from django.contrib import messages

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
    salt = ''.join(secrets.choice(string.ascii_letters + string.digits, k = 24))
    return salt


def derivate_passwd(salt, passwd):
    iterations = 500
    memory = 512
    parallelism = 2
    key_lenght = 48

    key = hashlib.argon2i(
        passwd.encode(),
        salt.encode(),
        iterations=iterations,
        memory_cost=memory,
        parallelism=parallelism,
        dklen=key_lenght
    )
    return binascii.hexlify(key).decode()


@decorators_admon_global.logged_required
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


class ActualizarAdministrador(UpdateView):
    model = models.Sysadmin
    form_class = forms.SinginAdmin
    template_name = 'editar_admin.html'
    success_url = reverse_lazy('listar_admin')


def CrearAdministrador(request):
    if request.method == 'GET':
        form = forms.SinginAdmin()
        context = {
            'form': form
        }
        return render(request, 'crear_admin.html', context)
    elif request.method == 'POST':
        form = forms.SinginAdmin(request.POST)
        if form.is_valid():
            data = form.cleaned_data

            cleaned_data = clean_specials(data)
            user_name=cleaned_data['user_name'],

            messages.success(request, f'Validaciones correctas {user_name}')
            return redirect('crear_admin')

            salt = gen_salt()
            hashed_passwd = derivate_passwd(salt, cleaned_data['passwd'])

            new_sysadmin = models.Sysadmin(
                user_name=cleaned_data['user_name'],
                passwd = hashed_passwd,
                chat_id = cleaned_data['chat_id'],
                token_bot = cleaned_data['token_bot'],
            )
            new_sysadmin.save()
            new_salt = models.Salt(
                content_object = new_sysadmin,
                salt_value = salt
            )
            new_salt.save()

            messages.success(request, 'El sysadmin se registró con éxito')
            return redirect('listar_admin')
        else:
            # El formulario no es válido, maneja los errores
            # ...
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


class CrearServer(CreateView):
    model = models.Servidor
    form_class = forms.SinginServer
    template_name = 'crear_server.html'
    success_url = reverse_lazy('listar_server')


class ListarServidor(ListView):
    model = models.Servidor
    template_name = 'listar_server.html'
    context_object_name = 'servers'
    queryset = models.Servidor.objects.all()


class ActualizarServidor(UpdateView):
    model = models.Servidor
    form_class = forms.SinginServer
    template_name = 'editar_server.html'
    success_url = reverse_lazy('listar_server')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['servers'] = models.Servidor.objects.filter(status=True)
        return context


class EliminarServidor(DeleteView):
    model = models.Servidor
    template_name = 'eliminar_server.html'
    success_url = reverse_lazy('listar_server')
