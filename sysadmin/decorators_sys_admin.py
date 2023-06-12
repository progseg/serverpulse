from django.http import HttpResponse, HttpResponseServerError
from django.shortcuts import redirect
from functools import wraps
from django.contrib import messages


def logged_required(view_func):
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        # Comprueba si el usuario está autenticado
        if not request.session.get('logged', False):
            messages.error(
                request, 'Necesita autenticarse para acceder al punto deseado')
            return redirect('login_sysadmin')

        # Ejecuta la vista original
        response = view_func(request, *args, **kwargs)

        # Asegúrate de que se devuelva una respuesta válida
        if not isinstance(response, HttpResponse):
            return HttpResponseServerError('Error interno del servidor')

        return response
    return wrapped_view
