from django.contrib import admin
from .models import *


@admin.register(AdmonGlobal)
class AdmonGlobalAdmin(admin.ModelAdmin):
    pass


@admin.register(Sysadmin)
class SysadminAdmin(admin.ModelAdmin):
    pass


@admin.register(Servidor)
class ServidorAdmin(admin.ModelAdmin):
    pass
# Register your models here.
