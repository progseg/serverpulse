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
from . import views


urlpatterns = [
    path('estado_apagado_servidor', views.estado_apagado_servidor,
         name='estado_apagado_servidor'),
    path('listar_servidores', views.listar_servidores, name='listar_servidores'),
    path('estado_servidor', views.estado_servidor, name='estado_servidor'),
    path('serializar_registros', views.serializar_registros,
         name='serializar_registros'),
    path('recuperar_registros', views.recuperar_registros,
         name='recuperar_registros'),
    path('monitor_data', views.monitor_data, name='monitor_data'),
]
