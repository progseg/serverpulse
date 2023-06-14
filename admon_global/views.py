from django.shortcuts import redirect, render
import logging
from django.http import HttpResponse, HttpRequest, HttpResponseNotAllowed
from django.urls import reverse_lazy
from . import decorators_admon_global
from django.views.decorators.csrf import csrf_protect
from auth_app import forms, models, views as auth_app
from django.views.generic import TemplateView, ListView, UpdateView, CreateView, DeleteView
# Create your views here.
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO,
                    filename='resgistroInicioAG.log', filemode='a')


@decorators_admon_global.logged_required
@csrf_protect
def dashboard_admon_global(request: HttpRequest) -> HttpResponse:
    logging.info(
        'dashboard Admin Global: Se hace petición por el método: ' + request.method)
    if request.method == 'GET':
        return render(request, 'dashboard.html')
    else:
        return HttpResponseNotAllowed[('GET')]


class ListarAdministrador(ListView):
    model = models.Sysadmin
    template_name = 'listar_admin.html'
    context_object_name = 'admins'
    queryset = models.Sysadmin.objects.all()


class ActualizarAdministrador(UpdateView):
    model = models.Sysadmin
    form_class = forms.SinginAdmin
    template_name = 'crear_admin.html'
    success_url = reverse_lazy('listar_admin')


class CrearAdministrador(CreateView):
    model = models.Sysadmin
    form_class = forms.SinginAdmin
    template_name = 'crear_admin.html'
    success_url = reverse_lazy('listar_admin')


class EliminarAdministrador(DeleteView):
    model = models.Sysadmin

    def post(self, request, pk, *args, **kwargs):
        object = models.Sysadmin.objects.get(nickname=pk)
        object.delete()
        return redirect("listar_admin")


class CrearServer(CreateView):
    model = models.Servidor
    form_class = forms.SinginServer
    template_name = 'crear_server.html'
    success_url = reverse_lazy('listar_server')


class ListarServidor(ListView):
    model = models.Servidor
    template_name = 'listar_server.html'
    context_object_name = 'servers'
    queryset = models.Servidor.objects.all()


class ActualizarServidor(UpdateView):
    model = models.Servidor
    form_class = forms.SinginServer
    template_name = 'editar_server.html'
    success_url = reverse_lazy('listar_server')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['servers'] = models.Servidor.objects.filter(status=True)
        return context

class EliminarServidor(DeleteView):
    model = models.Servidor

    def post(self, request, pk, *args, **kwargs):
        object = models.Servidor.objects.get(id=pk)
        object.estado = False
        object.save() 
        return redirect('listar_server')