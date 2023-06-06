from django.shortcuts import render
from django.http import HttpResponse, HttpRequest, HttpResponseNotAllowed
from . import decorators_sys_admin
from django.views.decorators.csrf import csrf_protect
# Create your views here.


@decorators_sys_admin.logged_required
@csrf_protect
def dashboard_sys_admin(request: HttpRequest) -> HttpResponse:
    if request.method == 'GET':
        return render(request, 'dashboard.html')
    else:
        return HttpResponseNotAllowed[('GET')]
