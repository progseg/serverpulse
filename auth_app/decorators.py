from django.http import HttpResponse, HttpResponseServerError
from django.shortcuts import redirect
from functools import wraps
from django.contrib import messages


def logged_required(view_func):
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        if not request.session.get('logged', False):
            messages.error(request, 'Necesita iniciar sesión para acceder a este punto')
            return redirect('login_sysadmin')
        
        return view_func(request, *args, **kwargs)

    return wrapped_view