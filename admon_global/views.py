from django.db import IntegrityError
from django.shortcuts import get_object_or_404, redirect, render
import logging
from django.http import HttpResponse, HttpRequest, HttpResponseNotAllowed
from django.urls import reverse_lazy
from . import decorators_admon_global
from django.views.decorators.csrf import csrf_protect
from auth_app import models
from . import forms
from django.utils.decorators import method_decorator
from django.views.generic import ListView, UpdateView, CreateView, DeleteView
from django.utils.html import escape
from django.contrib import messages
import bcrypt


# Create your views here.
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO,
                    filename='resgistroInicioAG.log', filemode='a')



def clean_specials(clean_data):
    """
    Limpia los caracteres especiales de los valores 
    del diccionario clean_data utilizando la función 
    escape() de la librería de escape especificada.

    Args:
        clean_data (dict): Un diccionario con los datos a limpiar.

    Returns:
        dict: Un nuevo diccionario con los valores limpios.
    """
    escaped_data = {}
    for field_name, field_value in clean_data.items():
        escaped_data[field_name] = escape(field_value)
    return escaped_data


def gen_salt():
    """
    Genera una sal utilizando la función bcrypt.gensalt() 
    y la devuelve como una cadena decodificada.

    Returns:
        str: La sal generada como una cadena decodificada.
    """
    salt = bcrypt.gensalt()
    return salt.decode()


def derivate_passwd(salt, passwd):
    """
    Deriva una contraseña utilizando una sal y una contraseña 
    dadas mediante la función bcrypt.hashpw().

    Args:
        salt (str): La sal utilizada para derivar la contraseña.
        passwd (str): La contraseña a derivar.

    Returns:
        str: La contraseña derivada como una cadena decodificada.

    Raises:
        Exception: Si ocurre un error durante la derivación 
        de la contraseña.
    """
    salt_bytes = salt.encode()
    passwd_bytes = passwd.encode()

    try:
        hashed_passwd = bcrypt.hashpw(passwd_bytes, salt_bytes)
        return hashed_passwd.decode()
    except Exception as e:
        raise e


@decorators_admon_global.logged_global_required
@csrf_protect
def dashboard_admon_global(request):
    """
    Vista para el panel de administración global.

    Args:
        request (HttpRequest): El objeto HttpRequest que 
        contiene los detalles de la solicitud.

    Returns:
        HttpResponse: La respuesta HTTP que muestra el 
        panel de administración global.
    """
    logging.info(
        'dashboard Admin Global: Se hace petición por el método: ' + request.method)
    if request.method == 'GET':
        return render(request, 'dashboard.html')
    else:
        return HttpResponseNotAllowed[('GET')]


@method_decorator(decorators_admon_global.logged_global_required, name='dispatch')
@method_decorator(csrf_protect, name='dispatch')
class ListarAdministrador(ListView):
    """
    Vista basada en clase para listar administradores.
       
    Returns:
        -: La respuesta HTTP que muestra el 
        panel de listar administrador.
    """
    model = models.Sysadmin
    template_name = 'listar_admin.html'
    context_object_name = 'admins'
    queryset = models.Sysadmin.objects.all()


@decorators_admon_global.logged_global_required
@csrf_protect
def update_sysadmin(request, uuid):
    """
    Vista para actualizar un administrador del sistema.

    Args:
        request (HttpRequest): El objeto HttpRequest que 
        contiene los detalles de la solicitud.
        uuid (str): El identificador único del administrador 
        del sistema a actualizar.

    Returns:
        HttpResponse: La respuesta HTTP que muestra el 
        formulario de actualización o redirige a la lista 
        de administradores.
    """
    sysadmin = get_object_or_404(models.Sysadmin, uuid=uuid)
    logging.info('update sysadmin: Accediendo a la función update_sysadmin')

    if request.method == 'GET':
        form = forms.UpdateSysadmin(instance=sysadmin)

        form.fields['user_name'].initial = sysadmin.user_name
        form.fields['chat_id'].initial = sysadmin.chat_id
        form.fields['token_bot'].initial = sysadmin.token_bot

        context = {
            'form': form,
            'uuid': uuid,
            'sysadmin': sysadmin
        }
        return render(request, 'editar_admin.html', context)
    
    if request.method == 'POST':
        form = forms.UpdateSysadmin(request.POST, instance=sysadmin)
        if form.is_valid():

            cleaned_data = form.cleaned_data
            cleaned_data = clean_specials(cleaned_data)

            if cleaned_data.get('passwd'):
                new_salt = gen_salt()
                try:
                    hashed_passwd = derivate_passwd(new_salt, cleaned_data['passwd'])
                except Exception as e:
                    messages.error(request, f'Error: {e}')
                    logging.error(f'update sysadmin: Error al derivar la contraseña: {e}')
                    return redirect('editar_admin')
                salt = sysadmin.salt
                salt.salt_value = new_salt
                salt.save()

                sysadmin.passwd = hashed_passwd
            if cleaned_data.get('user_name'):
                sysadmin.user_name = cleaned_data.get('user_name')

            if cleaned_data.get('chat_id'):
                sysadmin.chat_id = cleaned_data.get('chat_id')

            if cleaned_data.get('token_bot'):
                sysadmin.token_bot = cleaned_data.get('token_bot')
            
            try:
                sysadmin.save()
                messages.success(request, f'{sysadmin.user_name} actualizado')
                logging.info(f'update sysadmin: Administrador {sysadmin.user_name} actualizado')
                return redirect('listar_admin')
            except IntegrityError:
                messages.error(request, 'El nombre de usuario, Chat ID o token de bot ya existen')
                logging.error('update sysadmin: Error al guardar el administrador actualizado')
                return redirect('editar_admin', uuid=uuid)

                
        else:
            context = {
                'uuid': uuid,
                'sysadmin': sysadmin,
                'form': form
            }
            return render(request, 'editar_admin.html', context)
    else:
        logging.warning('update sysadmin: Método no permitido en la solicitud')
        return HttpResponseNotAllowed(['GET', 'POST'])


@decorators_admon_global.logged_global_required
@csrf_protect
def crear_administrador(request):
    """
    Vista para crear un administrador.

    Args:
        request (HttpRequest): El objeto HttpRequest 
        que contiene los detalles de la solicitud.

    Returns:
        HttpResponse: La respuesta HTTP que muestra 
        el formulario de creación o redirige a la lista 
        de administradores.
    """
    logging.info('crear administrador: Accediendo a la función crear_administrador')
    if request.method == 'GET':
        form = forms.SinginAdmin()
        context = {
            'form': form
        }
        return render(request, 'crear_admin.html', context)
    elif request.method == 'POST':
        form = forms.SinginAdmin(request.POST)
        if form.is_valid():
            cleaned_data = form.cleaned_data
            cleaned_data = clean_specials(cleaned_data)

            salt = gen_salt()
            try:
                hashed_passwd = derivate_passwd(salt, cleaned_data['passwd'])
            except Exception as e:
                messages.error(request, f'Error: {e}')
                logging.error(f'crear administrador: Error al derivar la contraseña: {e}')
                return redirect('crear_admin')

            new_salt = models.Salt(
                salt_value = salt
            )
            new_salt.save()

            new_sysadmin = models.Sysadmin(
                user_name=cleaned_data['user_name'],
                passwd = hashed_passwd,
                chat_id = cleaned_data['chat_id'],
                token_bot = cleaned_data['token_bot'],
                salt = new_salt
            )
            try:
                new_sysadmin.save()
                messages.success(request, 'El sysadmin se registró con éxito')
                logging.info(f'crear administrador: Administrador {new_sysadmin.user_name} creado')
                return redirect('listar_admin')
            except IntegrityError:
                messages.error(request, 'El nombre de usuario, el Chat ID o el token de bot ya existen')
                logging.error('crear administrador: Error al guardar el nuevo administrador')
                return redirect('crear_admin')

        else:
            context = {
                'form': form
            }
            return render(request, 'crear_admin.html', context)
    else:
        logging.warning('crear administrador: Método no permitido en la solicitud')
        return HttpResponseNotAllowed(['GET', 'POST'])


@method_decorator(decorators_admon_global.logged_global_required, name='dispatch')
@method_decorator(csrf_protect, name='dispatch')
class EliminarAdministrador(DeleteView):
    """
    Vista basada en clase para eliminar un administrador.

    Args:
        N/A

    Returns:
        Muestra una plantilla donde pregunta si puede 
        eliminar un sysadmin.
    """
    model = models.Sysadmin
    template_name = 'eliminar_admin.html'
    success_url = reverse_lazy('listar_admin')
    slug_field = 'uuid'
    slug_url_kwarg = 'uuid'
    
    def post(self, request, *args, **kwargs):
        """
        Procesa la solicitud POST para eliminar un administrador.

        Args:
            request (HttpRequest): El objeto HttpRequest que 
            contiene los detalles de la solicitud.
            *args: Argumentos adicionales.
            **kwargs: Argumentos de palabras clave adicionales.

        Returns:
            HttpResponse: La respuesta HTTP que muestra el 
            mensaje de éxito o error.
        """
        self.object = self.get_object()
        related_servers = models.Servidor.objects.filter(sysadmin=self.object)
        if related_servers.exists():
            messages.error(
                request,
                f"No se puede eliminar el Sysadmin '{self.object.user_name}' "
                f"porque está relacionado con los siguientes servidores: "
                f"{', '.join(str(server.ipv4_address) for server in related_servers)}. "
                "Por favor, cambie la relación con los servidores antes de eliminarlo."
            )
            logging.error('eliminar administrador: NO se puede eliminar al SysAdmin porque no esta relacionado con los servidores')
            return redirect('listar_admin')
        return super().post(request, *args, **kwargs)


@decorators_admon_global.logged_global_required
@csrf_protect
def crear_server(request):
    """
    Vista para crear un servidor.

    Args:
        request (HttpRequest): El objeto HttpRequest 
        que contiene los detalles de la solicitud.

    Returns:
        HttpResponse: La respuesta HTTP que muestra el 
        formulario de creación o redirige a la lista de 
        servidores.
    """
    logging.info('crear server: Accediendo a la función crear_server')
    if request.method == 'GET':
        form = forms.SinginServer()
        sysadmins = models.Sysadmin.objects.all()

        if not sysadmins:
            messages.error(request, 'Antes de registrar un servidor, debe crear un sysadmin')
            logging.warning('crear server: No hay sysadmins registrados antes de crear un servidor')
            return redirect('listar_server')

        context = {
            'form': form,
            'sysadmins': sysadmins
        }

        return render(request, 'crear_server.html', context)
    
    elif request.method == 'POST':
        form = forms.SinginServer(request.POST)
        if form.is_valid():

            cleaned_data = form.cleaned_data
            cleaned_data = clean_specials(cleaned_data)

            salt = gen_salt()
            try:
                hashed_passwd = derivate_passwd(salt, cleaned_data['passwd'])
            except Exception as e:
                messages.error(request, f'Error: {e}')
                logging.error(f'crear server: Error al derivar la contraseña: {e}')
                return redirect('crear_admin')

            new_salt = models.Salt(
                salt_value = salt
            )
            new_salt.save()

            sysadmin_uuid = cleaned_data['sysadmin']
            sysadmin_instance = get_object_or_404(models.Sysadmin, uuid = sysadmin_uuid)

            new_server = models.Servidor(
                ipv4_address=cleaned_data['ipv4_address'],
                passwd = hashed_passwd,
                sysadmin = sysadmin_instance,
                salt = new_salt
            )

            try:
                new_server.save()
                messages.success(request, 'El servidor ha sido registrado con éxito')
                logging.info(f'crear server: Servidor {new_server.ipv4_address} creado')
                return redirect('listar_server')
            except  IntegrityError:
                messages.error(request, 'El nombre de usuario, el Chat ID o el token de bot ya existen')
                logging.error('crear server: Error al guardar el nuevo servidor')
                return redirect('crear_server')
        else:
            sysadmins = models.Sysadmin.objects.all()

            if not sysadmins:
                messages.error(request, 'Antes de registrar un servidor, debe crear un sysadmin')
                logging.warning('crear server: No hay sysadmins registrados antes de crear un servidor')
                return redirect('listar_server')
            context = {
                'form': form,
                'sysadmins': sysadmins
            }
            return render(request, 'crear_server.html', context)
    else:
        logging.warning('crear server: Método no permitido en la solicitud')
        return HttpResponseNotAllowed(['GET', 'POST'])


@method_decorator(decorators_admon_global.logged_global_required, name='dispatch')
@method_decorator(csrf_protect, name='dispatch')
class ListarServidor(ListView):
    """
    Vista basada en clase para listar los servidores.

    Args:
        N/A

    Returns:
        Muestra una plantilla donde lista los servidores
        disponibles.
    """
    model = models.Servidor
    template_name = 'listar_server.html'
    context_object_name = 'servers'
    queryset = models.Servidor.objects.all()


@decorators_admon_global.logged_global_required
@csrf_protect
def update_servidor(request, uuid):
    """
    Vista para actualizar un servidor.

    Args:
        request (HttpRequest): El objeto HttpRequest 
        que contiene los detalles de la solicitud.
        uuid (str): El identificador único del servidor.

    Returns:
        HttpResponse: La respuesta HTTP que muestra 
        el formulario de actualización o redirige 
        a la lista de servidores.
    """
    logging.info(f'update server: Accediendo a la función update_servidor para el servidor con UUID {uuid}')
    servidor = get_object_or_404(models.Servidor, uuid=uuid)
    
    if request.method == 'GET':
        form = forms.UpdateServer(instance=servidor)

        form.fields['ipv4_address'].initial = servidor.ipv4_address

        context = {
            'form': form,
            'uuid': uuid,
            'servidor': servidor
        }
        return render(request, 'editar_server.html', context)
    
    if request.method == 'POST':
        form = forms.UpdateServer(request.POST, instance=servidor)
        if form.is_valid():

            cleaned_data = form.cleaned_data
            cleaned_data = clean_specials(cleaned_data)

            if cleaned_data.get('passwd'):
                new_salt = gen_salt()
                try:
                    hashed_passwd = derivate_passwd(new_salt, cleaned_data['passwd'])
                except Exception as e:
                    messages.error(request, f'Error: {e}')
                    logging.error(f'update server: Error al derivar la contraseña: {e}')
                    return redirect('crear_server')
                salt = servidor.salt
                salt.salt_value = new_salt
                servidor.passwd = hashed_passwd
                salt.save()

            if cleaned_data.get('ipv4_address'):
                servidor.ipv4_address = cleaned_data.get('ipv4_address')

            try:
                servidor.save()
                messages.success(request, f'{servidor.ipv4_address} actualizado')
                logging.info(f'update server: Servidor {servidor.ipv4_address} actualizado')
                return redirect('listar_server')
            except IntegrityError:
                messages.error(request, 'La dirección IPv4 ya está en uso')
                logging.error('update server: Error al guardar los cambios en el servidor')
                return redirect('editar_server', uuid=uuid)
        else:
            context = {
                'uuid': uuid,
                'servidor': servidor,
                'form': form
            }
            return render(request, 'editar_server.html', context)
    else:
        logging.warning('update server: Método no permitido en la solicitud')
        return HttpResponseNotAllowed(['GET', 'POST'])


@method_decorator(decorators_admon_global.logged_global_required, name='dispatch')
@method_decorator(csrf_protect, name='dispatch')
class EliminarServidor(DeleteView):
    """
    Vista basada en clase para eliminar un servidor.

    Args:
        N/A

    Returns:
        Muestra una plantilla donde pregunta si puede 
        eliminar un servidor.
    """
    model = models.Servidor
    template_name = 'eliminar_server.html'
    success_url = reverse_lazy('listar_server')
    slug_field = 'uuid'
    slug_url_kwarg = 'uuid'


@decorators_admon_global.logged_global_required
@csrf_protect
def change_relation(request, uuid):
    """
    Vista para cambiar la relación entre un 
    servidor y un sysadmin.

    Args:
        request (HttpRequest): El objeto HttpRequest 
        que contiene los detalles de la solicitud.
        uuid (str): El identificador único del servidor.

    Returns:
        HttpResponse: La respuesta HTTP que muestra el 
        formulario de actualización de la relación o 
        redirige a la lista de servidores.
    """
    logging.info(f'asociar admins/server: Accediendo a la función change_relation para el servidor con UUID {uuid}')
    servidor = get_object_or_404(models.Servidor, uuid=uuid)
    sysadmins = models.Sysadmin.objects.all()

    if request.method == 'GET':
        form = forms.RelationSysadminServer(instance=servidor)

        context = {
            'form': form,
            'sysadmins': sysadmins
        }
        return render(request, 'editar_relacion.html', context)
    
    elif request.method == 'POST':
        form = forms.RelationSysadminServer(request.POST, instance=servidor)

        if form.is_valid():
            form.save()
            messages.success(request, 'Relación actualizada')
            logging.info('asociar admins/server: Relación entre el servidor y el sysadmin actualizada')
            return redirect('listar_server')
        else:
            context= {
                'form': form,
                'uuid': uuid
            }
            return render(request, 'editar_relacion.html', context)
    else:
        logging.warning('asociar admins/server: Método no permitido en la solicitud')
        return HttpResponseNotAllowed(['GET', 'POST'])

