from django.http import HttpResponse, HttpResponseServerError
from django.shortcuts import redirect
from functools import wraps
from django.contrib import messages
import logging

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO,
                    filename='resgistros.log', filemode='a')


def logged_required(view_func):
    """
    Decorador que requiere que el usuario haya iniciado 
    sesión para acceder a una vista.

    Args:
    - view_func: La función de vista a decorar.

    Retuns:
    - wrapped_view: La vista decorada que verifica si el 
    usuario ha iniciado sesión. Si no ha iniciado sesión, 
    se redirige a la página de inicio de sesión y se muestra 
    un mensaje de error.
    """
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        logging.info('Verificando si el usuario ha iniciado sesión')
        if not request.session.get('logged', False):
            logging.warning('El usuario intentó acceder a una vista protegida sin iniciar sesión')
            messages.error(request, 'Necesita iniciar sesión para acceder a este punto')
            return redirect('login_sysadmin')
        
        logging.info('El usuario ha iniciado sesión correctamente')
        return view_func(request, *args, **kwargs)

    return wrapped_view