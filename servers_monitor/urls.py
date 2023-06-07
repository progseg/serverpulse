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
    path('state_servidor', views.state_servidor,
         name='state_servidor'),
    path('on_servidor', views.on_servidor,
         name='on_servidor'),
    path('off_servidor', views.off_servidor,
         name='off_servidor'),
    path('indeterminate_servidor', views.indeterminate_servidor,
         name='indeterminate_servidor'),
    path('recuperar_registros', views.recuperar_registros,
         name='recuperar_registros'),
    path('serializar_registros', views.serializar_registros,
         name='serializar_registros')
]