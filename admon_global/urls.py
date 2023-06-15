"""serverPulse URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path
from .views import *
from django.contrib.auth.decorators import login_required

urlpatterns = [
    # Inicio
    path('dashboard_admon_global', dashboard_admon_global,
         name='dashboard_admon_global'),
    # Configuración SysAdmin
    path('crear_admin/', crear_administrador,
         name='crear_admin'),
    path('listar_admin/', ListarAdministrador.as_view(),
         name='listar_admin'),
    path('editar_admin/<uuid:uuid>/',
         update_sysadmin, name='editar_admin'),
    path('eliminar_admin/<uuid:uuid>/',
         EliminarAdministrador.as_view(), name='eliminar_admin'),
    # Configuración Server
    path('listar_server/', ListarServidor.as_view(),
         name='listar_server'),
    path('crear_server/', crear_server, name='crear_server'),
    path('editar_server/<uuid:uuid>/',
         update_servidor, name='editar_server'),
    path('eliminar_server/<uuid:uuid>/',
         EliminarServidor.as_view(), name='eliminar_server')
]
