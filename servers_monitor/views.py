from django.shortcuts import render
import logging
from django.http import HttpResponse, HttpRequest, HttpResponseNotAllowed, JsonResponse
from auth_app import forms, models, views as auth_app

# Create your views here.
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO,
                    filename='resgistroInicioAG.log', filemode='a')


def get_client_ip(request):
    logging.info(
        'get_client_ip Monitoreo: Se hace petición por el método: ' + request.method)
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def monitor(request):
    logging.info(
        'monitor Monitoreo: Se hace petición por el método: ' + request.method)
    template = 'monitoreo.html'
    if request.method == 'GET':
        return render(request, template)


def state_servidor(request):
    logging.info(
        'Estado del servidor Monitoreo: Se hace petición por el método: ' + request.method)
    template = 'monitoreo.html'
    d = {'list': models.Servidor.objects.all()}
    return render(request, template, d)


def on_servidor(request):
    logging.info(
        'Servidor Activo Monitoreo: Se hace petición por el método: ' + request.method)
    template = 'monitoreo.html'
    d = {'list': models.Servidor.objects.all()}
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
    logging.info(
        'Servidor Apagado Monitoreo: Se hace petición por el método: ' + request.method)
    address = get_client_ip(request)
    for server in models.Servidor.objects.all():
        if address == server.ipv4_address:
            print("Apagado")
            server.status = "Apagado"
            server.save()
    return HttpResponse("Apagado")


def comparar_ip(request):
    t = 'monitoreo.html'
    d = {'list': models.Servidor.objects.all()}
    solicitud = get_client_ip(request)
    for servidor in models.Servidor.objects.all():
        if solicitud == servidor.Direccion:
            servidor.status = "Encendido"
            servidor.save()
        else:
            servidor.status = "Indeterminado"
            servidor.save()
    return render(request, t, d)


def recuperar_registros(request):
    logging.info(
        'recupertar_registros AJAX Monitoreo: Se hace petición por el método: ' + request.method)
    servs = models.Servidor.objects.all()
    result = serializar_registros(servs)
    return JsonResponse(result, safe=False)


def serializar_registros(servs):
    result = []
    for register in servs:
        result.append({'Direccion': register.ipv4_address,
                      'Estado': register.status})
    return result
