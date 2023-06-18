import docker
from django.shortcuts import render
from auth_app import models

def terminal_view(request, uuid):
    # Obtener el servidor correspondiente
    servidor = models.Servidor.objects.get(uuid=uuid)

    # Verificar si se ha enviado el formulario
    if request.method == 'POST':
        # Obtener la contraseña ingresada por el usuario
        contraseña_ingresada = request.POST['contraseña']

        client = docker.from_env()

        # Definir las variables de entorno para el contenedor de terminal
        environment = {
            'TERMINAL_IPV4': servidor.ipv4,
            'TERMINAL_PASSWORD': servidor.passwd
        }

        # Crear el contenedor utilizando el Docker Compose
        container = client.containers.run(
            'nombre_del_contenedor_terminal',  # Reemplaza con el nombre de tu contenedor
            detach=True,
            environment=environment,
            ports={'7681': 6767},  # Mapear el puerto del contenedor al host
            network='nombre_de_tu_red',  # Reemplaza con el nombre de tu red Docker
        )

        # Obtener la dirección IP del contenedor
        ip_contenedor = container.attrs['NetworkSettings']['Networks']['nombre_de_tu_red']['IPAddress']

        # Renderizar la plantilla con la dirección IP del contenedor
        return render(request, 'terminal.html', {'ip_contenedor': ip_contenedor})

    # Renderizar la plantilla del formulario para solicitar la contraseña
    return render(request, 'solicitar_terminal.html', {'servidor': servidor})
