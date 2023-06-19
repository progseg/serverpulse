from django.shortcuts import render
import logging
from django.http import HttpResponse, HttpRequest, HttpResponseNotAllowed
from . import decorators_sys_admin
from django.views.decorators.csrf import csrf_protect
from auth_app import models
# Create your views here.
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO,
                    filename='resgistroInicioAG.log', filemode='a')


@decorators_sys_admin.logged_sysadmin_required
@csrf_protect
def dashboard_sys_admin(request: HttpRequest) -> HttpResponse:
    logging.info(
        'dashboard Sys Admin: Se hace petición por el método: ' + request.method)
    if request.method == 'GET':
        return render(request, 'dashboard_sysadmin.html')
    else:
        return HttpResponseNotAllowed[('GET')]

@decorators_sys_admin.logged_sysadmin_required
@csrf_protect
def server_list(request):
    uuid = request.session.get('uuid')
    sysadmin = models.Sysadmin.objects.get(uuid=uuid)
    user_name=sysadmin.user_name

    servidores = models.Servidor.objects.filter(sysadmin=sysadmin)

    context = {
        'servidores': servidores,
        'username': user_name,
    }
    return render(request, 'server_list.html', context)
