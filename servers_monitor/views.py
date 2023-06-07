from django.shortcuts import render
from django.http import HttpResponse, HttpRequest, HttpResponseNotAllowed
from . import decorators_sys_admin
from . import models

# Create your views here.
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def monitor(request):
    template = 'monitoreo.html'
    if request.method == 'GET':
        return render(request, template)


def state_servidor(request):
    template='monitoreo.html'
    d={'list':models.Servidor.objects.all()}
    return render(request, template, d)


def monitor_cpu(request):
    template='monitoreo.html'
    d={'list':models.Servidor.objects.get}
    pass


def on_servidor(request):
    template='monitoreo.html'
    d={'list':models.Servidor.objects.all()}
    address = get_client_ip(request)
    status = "Activo"
    for server in models.Servidor.objects.all():
        if address == server.ipv4_address:
            server.status = "Activo"
            server.save()
        else:
            indeterminate_servidor(server)
    return HttpResponse("Activo")


def indeterminate_servidor(server):
    if server.status != "Apagado":
        server.status = "Indeterminado"
        server.save()


def off_servidor(request):
    address = get_client_ip(request)
    for server in models.Servidor.objects.all():
        if address == server.ipv4_address:
            print("Apagado")
            server.status = "Apagado"
            server.save()
    return HttpResponse("Apagado")

