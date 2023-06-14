from django.http import HttpResponse, HttpResponseServerError
from django.shortcuts import redirect
from functools import wraps
from django.contrib import messages
from django.utils.decorators import method_decorator


def logged_required(view_func):
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        # Comprueba si el usuario está autenticado
        if not request.session.get('logged', False):
            messages.error(
                request, 'Necesita autenticarse para acceder al punto deseado')
            return redirect('login_admon_global')

        # Ejecuta la vista original
        response = view_func(request, *args, **kwargs)

        # Asegúrate de que se devuelva una respuesta válida
        if not isinstance(response, HttpResponse):
            return HttpResponseServerError('Error interno del servidor')

        return response
    return wrapped_view
"""
def class_view_decorator(function_decorator):
    def deco(View):
        View.dispatch = method_decorator(function_decorator)(View.dispatch)
        return View
    return deco
"""