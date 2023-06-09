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
    path('dashboard_admon_global', views.dashboard_admon_global,
         name='dashboard_admon_global'),
    path('list_date', views.list_date, name='list_date'),
    path('edit_server/<int:id>/', views.edit_server, name='edit_server'),
    path('delete_server/<int:id>/', views.edit_server, name='edit_server'),
    path('edit_sysadmin/<int:id>/', views.edit_sysadmin, name='edit_sysadmin'),
    path('delete_sysadmin/<int:id>/', views.delete_sysadmin, name='delete_sysadmin')
]
