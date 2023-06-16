from django.shortcuts import render
import logging
from django.http import HttpResponse, HttpRequest, HttpResponseNotAllowed, JsonResponse
from auth_app import forms, models, views as auth_app
from django.views.decorators.csrf import csrf_exempt

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


@csrf_exempt
def estado_servidor(request):
    template = 'monitoreo.html'
    objeto = {'list': models.Servidor.objects.all()}
    return render(request, template, objeto)


def listar_servidores(request):
    direccion = get_client_ip(request)
    for server in models.Servidor.objects.all():
        if direccion == server.ipv4_address:
            server.status = "Encendido"
            server.save()
        else:
            estado_indeterminado_servidor(server)
    return HttpResponse("Encendido")


def estado_indeterminado_servidor(server):
    if server.status != "Apagado":
        server.status = "Indeterminado"
        server.save()


def estado_apagado_servidor(request):
    direccion = get_client_ip(request)
    for server in models.Servidor.objects.all():
        if direccion == server.ipv4_address:
            server.status = "Apagado"
            server.save()
    return HttpResponse("Apagado")


def comparar_direccion_ip(request):
    template = 'monitoreo.html'
    objeto = {'list': models.Servidor.objects.all()}
    solicitud = get_client_ip(request)
    for servidor in models.Servidor.objects.all():
        if solicitud == servidor.ipv4_address:
            servidor.status = "Activo"
            servidor.save()
        else:
            servidor.status = "Indeterminado"
            servidor.save()
    return render(request, template, objeto)


def recuperar_registros(request):
    logging.info(
        'recupertar_registros AJAX Monitoreo: Se hace petición por el método: ' + request.method)
    servs = models.Servidor.objects.all()
    result = serializar_registros(servs)
    return JsonResponse(result, safe=False)


@csrf_exempt
def serializar_registros(servs):
    result = []
    for register in servs:
        result.append({'Direccion': register.ipv4_address,
                      'Estado': register.status})
    return result


@csrf_exempt
def monitor_data(request):
    if request.method == 'POST':
        cpu_usage = request.POST.get('cpu_usage')
        processor_details = request.POST.get('processor_details')
        disk_usage = request.POST.get('disk_usage')
        context = {
            'cpu_usage': cpu_usage,
            'processor_details': processor_details,
            'disk_usage': disk_usage
        }
        return render(request, 'monitoreo.html', context)
    else:
        return HttpResponse('Método no permitido')
