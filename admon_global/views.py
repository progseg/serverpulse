from django.shortcuts import render
import logging
from django.http import HttpResponse, HttpRequest, HttpResponseNotAllowed
from . import decorators_admon_global
from django.views.decorators.csrf import csrf_protect
from auth_app import views as auth_app
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


def edit_server(request: HttpRequest) -> HttpResponse:
    template = 'edit_server.html'
    if request.method == 'GET':
        return render(request, template)
