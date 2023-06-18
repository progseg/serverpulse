from django.shortcuts import render
import logging
from django.http import HttpResponse, HttpRequest, JsonResponse
from auth_app import models
from django.views.decorators.csrf import csrf_exempt

# Create your views here.
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO,
                    filename='resgistroInicioAG.log', filemode='a')


def get_client_ip(request: HttpRequest) -> HttpResponse:
    """
    Esta función recupera la dirección IP del cliente de la 
    solicitud HTTP. Primero verifica el HTTP_X_FORWARDED_FOR
    encabezado y, si no está presente, recurre al REMOTE_ADDR
    atributo en los metadatos de la solicitud.
    Args:
        request (HttpRequest): 

    Returns:
        HttpResponse: 
    """
    logging.info(
        'get_client_ip Monitoreo: Se hace petición por el método: ' + request.method)
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@csrf_exempt
def estado_servidor(request: HttpRequest) -> HttpResponse:
    """
    Maneja la solicitud del estado del servidor y genera una
    plantilla llamada "monitoreo.html". Recupera todos los 
    objetos del servidor de la base de datos y los pasa 
    como una variable de contexto.
    Args:
        request (HttpRequest): 

    Returns:
        HttpResponse: 
    """
    template = 'monitoreo.html'
    objeto = {'list': models.Servidor.objects.all()}
    return render(request, template, objeto)


def listar_servidores(request: HttpRequest) -> HttpResponse:
    """
    Esta función compara la dirección IP del cliente con las 
    direcciones IP de todos los objetos del servidor. Si se 
    encuentra una coincidencia, el estado del servidor se 
    establece en "Encendido", y si no, se establecer el 
    estado del servidor en "Indeterminado".
    Args:
        request (HttpRequest): 

    Returns:
        HttpResponse: 
    """
    direccion = get_client_ip(request)
    for server in models.Servidor.objects.all():
        if direccion == server.ipv4_address:
            server.status = "Encendido"
            server.save()
        else:
            estado_indeterminado_servidor(server)
    return HttpResponse("Encendido")


def estado_indeterminado_servidor(server):
    """
    Esta función establece el estado del 
    servidor en "Indeterminado" si aún no 
    está configurado en "Apagado" (apagado).
    Args:
        server: Tipo de estado
    """
    if server.status != "Apagado":
        server.status = "Indeterminado"
        server.save()


def estado_apagado_servidor(request: HttpRequest) -> HttpResponse:
    """
    Esta función establece el estado del servidor en "Apagado" si 
    la dirección IP del cliente coincide con la dirección IP de 
    cualquier servidor.
    Args:
        request (HttpRequest): 

    Returns:
        HttpResponse: 
    """
    direccion = get_client_ip(request)
    for server in models.Servidor.objects.all():
        if direccion == server.ipv4_address:
            server.status = "Apagado"
            server.save()
    return HttpResponse("Apagado")


def comparar_direccion_ip(request: HttpRequest) -> HttpResponse:
    """
    Esta función compara la dirección IP del cliente con las 
    direcciones IP de todos los objetos del servidor. Si se 
    encuentra una coincidencia, el estado del servidor se establece
    en "Activo", y si no, se establece en "Indeterminado".
    Args:
        request (HttpRequest): 

    Returns:
        HttpResponse: 
    """
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


def recuperar_registros(request: HttpRequest) -> HttpResponse:
    """
    Esta función recupera todos los objetos del servidor de la 
    base de datos y los serializa en una respuesta JSON mediante 
    la función serializar_registros.
    Args:
        request (HttpRequest): _description_

    Returns:
        HttpResponse: _description_
    """
    logging.info(
        'recupertar_registros AJAX Monitoreo: Se hace petición por el método: ' + request.method)
    servs = models.Servidor.objects.all()
    result = serializar_registros(servs)
    return JsonResponse(result, safe=False)


@csrf_exempt
def serializar_registros(servs):
    """
    Esta función serializa una lista de 
    objetos de servidor en una lista de 
    diccionarios, donde cada diccionario 
    contiene la dirección IP y el estado 
    del servidor.
    Args:
        servs(list): Contiene los objetos como
                     dirección ip y el estado

    Returns:
        data: 
    """
    result = []
    for register in servs:
        result.append({'Direccion': register.ipv4_address,
                      'Estado': register.status})
    return result


@csrf_exempt
def monitor_data(request):
    if request.method == 'GET':
        cpu_percent = request.GET.get('cpu_percent')
        memory_percent = request.GET.get('memory_percent')
        disk_percent = request.GET.get('disk_percent')
        print(cpu_percent)
        print(memory_percent)
        print(disk_percent)
        response_data = {
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'disk_percent': disk_percent
        }
        return JsonResponse(response_data, safe=False)
    else:
        return JsonResponse({'error': 'Método no permitido'})
        

def monitor(request):
    return render(request, 'monitoreo.html')