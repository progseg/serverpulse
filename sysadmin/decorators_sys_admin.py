from django.http import HttpResponse, HttpResponseServerError
from django.shortcuts import redirect
from functools import wraps
from django.contrib import messages


def logged_sysadmin_required(view_func):
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        if request.session.get('role') != 'sysadmin':
            messages.error(request, 'No tiene permisos para acceder a este sitio')
            return redirect('login_sysadmin')
        
        return view_func(request, *args, **kwargs)

    return wrapped_view