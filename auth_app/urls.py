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
from django.urls import include


urlpatterns = [
    path('singin/', views.singin, name='singin'),
    path('login_admon_global', views.login_admon_global, name='login_admon_global'),
    #    path('login_sysadmin', views.login_sysadmin, name='login_sysadmin'),
    path('request_token_admon_global', views.request_token_admon_global,
         name='request_token_admon_global'),
    #    path('request_token_sysadmin', views.request_token_sysadmin,
    #         name='request_token_sysadmin'),
    path('dashboard_admon_global', views.dashboard_admon_global,
         name='dashboard_admon_global'),
    path('accounts/login', include('django.contrib.auth.urls'))
]
