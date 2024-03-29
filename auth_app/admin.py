from typing import Any, List, Optional, Tuple, Union
from django.contrib import admin
from django.http.request import HttpRequest
from .models import *
from . import forms


@admin.register(AdmonGlobal)
class AdmonGlobalAdmin(admin.ModelAdmin):
    readonly_fields = (
        'uuid',
        'token_double_auth',
        'intentos',
        'timestamp_ultimo_intento',
        'timestamp_token_double_auth',
        'ipv4_address',
        'salt'
    )
    def get_readonly_fields(self, request: HttpRequest, obj: Any | None = None) -> List[str] | Tuple[Any, ...]:
        if request.user.is_superuser:
            return self.readonly_fields
        else:
            return[]


@admin.register(Sysadmin)
class SysadminAdmin(admin.ModelAdmin):
    readonly_fields = (
        'uuid',
        'user_name',
        'passwd',
        'chat_id',
        'token_bot',
        'token_double_auth',
        'intentos',
        'timestamp_ultimo_intento',
        'timestamp_token_double_auth',
        'ipv4_address',
        'salt'
    )
    def get_readonly_fields(self, request: HttpRequest, obj: Any | None = None) -> List[str] | Tuple[Any, ...]:
        if request.user.is_superuser:
            return self.readonly_fields
        else:
            return[]
    
    #def has_delete_permission(self, request: HttpRequest, obj: Any | None = ...) -> bool:
    #    if request.user.is_superuser:
    #        return False
    #    return super().has_delete_permission(request, obj)
    
    def has_change_permission(self, request: HttpRequest, obj: Any | None = ...) -> bool:
        if request.user.is_superuser:
            return False
        return super().has_change_permission(request, obj)
    
    def has_add_permission(self, request: HttpRequest) -> bool:
        if request.user.is_superuser:
            return False
        return super().has_add_permission(request)


@admin.register(Servidor)
class ServidorAdmin(admin.ModelAdmin):
    readonly_fields = (
        'ipv4_address',
        'passwd',
        'status',
        'sysadmin',
        'salt',
        'uuid'
    )
    def get_readonly_fields(self, request: HttpRequest, obj: Any | None = None) -> List[str] | Tuple[Any, ...]:
        if request.user.is_superuser:
            return self.readonly_fields
        else:
            return[]
    
    #def has_delete_permission(self, request: HttpRequest, obj: Any | None = ...) -> bool:
    #    if request.user.is_superuser:
    #        return False
    #    return super().has_delete_permission(request, obj)
    
    def has_change_permission(self, request: HttpRequest, obj: Any | None = ...) -> bool:
        if request.user.is_superuser:
            return False
        return super().has_change_permission(request, obj)
    
    def has_add_permission(self, request: HttpRequest) -> bool:
        if request.user.is_superuser:
            return False
        return super().has_add_permission(request)


@admin.register(Salt)
class SaltAdmin(admin.ModelAdmin):
    readonly_fields = ['salt_value']
    
    #def has_delete_permission(self, request: HttpRequest, obj: Any | None = ...) -> bool:
    #    if request.user.is_superuser:
    #        return False
    #    return super().has_delete_permission(request, obj)
    
    def has_change_permission(self, request: HttpRequest, obj: Any | None = ...) -> bool:
        if request.user.is_superuser:
            return False
        return super().has_change_permission(request, obj)
    
    def has_add_permission(self, request: HttpRequest) -> bool:
        if request.user.is_superuser:
            return False
        return super().has_add_permission(request)
# Register your models here.
