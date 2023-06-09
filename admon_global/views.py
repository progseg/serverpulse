from pyexpat.errors import messages
from django.shortcuts import get_object_or_404, redirect, render
import logging
from django.http import HttpResponse, HttpRequest, HttpResponseNotAllowed
from . import decorators_admon_global
from django.views.decorators.csrf import csrf_protect
from auth_app import forms, models, views as auth_app
from django.contrib.auth.hashers import make_password, check_password
# Create your views here.
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO,
                    filename='resgistroInicioAG.log', filemode='a')


@decorators_admon_global.logged_required
@csrf_protect
def dashboard_admon_global(request: HttpRequest) -> HttpResponse:
    logging.info(
        'dashboard Admin Global: Se hace petición por el método: ' + request.method)
    if request.method == 'GET':
        return render(request, 'dashboard.html')
    else:
        return HttpResponseNotAllowed[('GET')]


def list_date(request: HttpRequest) -> HttpResponse:
    template = 'list_date.html'
    if request.method == 'GET':
        return render(request, template)

def delete_server(request: HttpRequest, id) -> HttpRequest:
    serv = get_object_or_404(forms.SinginServers, pk=id)
    if request.method == 'POST':
        serv.delete()
    return redirect('/list_date')

def edit_server(request: HttpRequest, id) -> HttpRequest:
    serv = get_object_or_404(forms.SinginServers, pk=id)
    if request.method == 'POST':
        form_singin_server = forms.SinginServers(request.POST, isinstance=serv)
        if form_singin_server.is_valid():
            ipv4_address = form_singin_server.cleaned_data['ipv4_address']
            password = form_singin_server.cleaned_data['password'] = make_password(password)

            Servidor = models.Servidor()

            Servidor.ipv4_address = ipv4_address
            Servidor.password = password

            try:
                Servidor.save()

                messages.success(
                    request, 'El servidor {ipv4_address} fue registrado con éxito')
                logging.info(
                    'Singin Servidor: El servidor ingreso adecuadamente en su sesión')
                return redirect('list_date')
            except:
                messages.error(
                    request, 'Ocurrió un error inesperado en el servidor')
                logging.error(
                    'Singin Servidor: Error en el servidor')
                return redirect('edit_server')
        else:
            form_singin_server = forms.SinginServers()
            messages.error(request, 'Los datos proporcionados no son válidos')
            logging.error(
                'Singin Servidor: Los datos que ingreso el usuario no son correctos')
            return redirect('edit_server')
    return redirect('/list_date')


