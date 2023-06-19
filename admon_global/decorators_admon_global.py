from django.http import HttpResponse, HttpResponseServerError
from django.shortcuts import redirect
from functools import wraps
from django.contrib import messages
import logging

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO,
                    filename='resgistroInicioAG.log', filemode='a')


def logged_global_required(view_func):
    """
    Decorador para verificar si el usuario está autenticado 
    y tiene los permisos adecuados.

    Args:
        view_func (function): La función de vista original a decorar.

    Returns:
        function: La vista decorada.
    """
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        """
        Función de vista envuelta que realiza la verificación de 
        autenticación y permisos.

        Args:
            request (HttpRequest): La solicitud HTTP.
            *args: Argumentos posicionales adicionales.
            **kwargs: Argumentos de palabras clave adicionales.

        Returns:
            HttpResponse: La respuesta de la vista original o un 
            HttpResponseServerError si hay un error interno del servidor.
        """
        # Comprueba si el usuario está autenticado
        if not request.session.get('logged', False):
            messages.error(
                request, 'Necesita autenticarse para acceder al punto deseado'
            )
            logging.error(
                'Usuario no autenticado intentó acceder a la vista: {}'.format(request.path))
            return redirect('login_sysadmin')
        if request.session.get('role') != 'global':
            messages.error(
                request, 'No tiene permisos para acceder a este sitio'
            )
            logging.warning(
                'Usuario sin permisos intentó acceder a la vista: {}'.format(request.path))
            return redirect('login_admon_global')

        # Ejecuta la vista original
        response = view_func(request, *args, **kwargs)

        # Asegúrate de que se devuelva una respuesta válida
        if not isinstance(response, HttpResponse):
            logging.error(
                'La vista no devolvió una respuesta válida: {}'.format(request.path))
            return HttpResponseServerError('Error interno del servidor')

        return response
    return wrapped_view
