# serverpulse

## Funcionalidades

### Administrador global:
- :accept: Registra, actualiza y elimina servidores de la infraestructura
- :accept: Registrar, actualizar y eliminar administradores de servidores
- :accept: Asociar servidores a administradores (un servidor sólo puede ser administrado por un administrador)

### Administradores de servidor:
- :accept: Iniciar sesión (sus credenciales son provistas por el administrador global por fuera del sistema, así como cualquier otra información de seguridad que necesite el administrador)
- Monitorizar servidor: por cada servidor asociado el administrador puede ver:
  + Porcentaje de uso de procesador
  + Porcentaje de uso de memoria
  + Porcentaje de uso de disco
  + Puntos extra: mandar una notificación por fuera del sistema (a telegram por ejemplo) si algún servidor cae
- Conectarse al servidor: a través de la misma interfaz web (no usar ssh por fuera) se puede abrir una terminal hacía el servidor

## Prácticas

### Parcial - jueves 1 de junio del 2023

- :accept: repositorio de código

  - :accept: github clonado
  - :accept: agregar compañeros
  - :accept: todos deben tener un clon del repo

- :accept: análisis de código estático

  - :accept: instalar sonarqube
  - :accept: scannear el proyecto
  - :accept: asignar tareas (autoasignarse tareas)
  - :accept: generar reporte de mitigaciones

- :accept: manejo de configuración sensible

  - :accept: crear sistema web
  - :accept: configurar para usar SMBD
  - :accept: separar configuraciones sensibles de settings en un archivo .env
  - :accept: hacer script para inicilizar el ambiente de depuración con seguridad
  - :accept: subir evidencias a Github

- :accept: almacenamiento de información sensible

  - :accept: registro de usuarios con políticas de contraseñas (10char,uppercase,lowecase,digits,special)
  - :accept: hashing de contraseñas con salt y algoritmo seguro
  - :accept: validaciones de entradas externas

- :yellow_circle: manejo seguro de sesiones web y cookies
  - :accept: configurar sesiones seguras: logout
  - :accept: configurar sesiones seguras: settings
  - :accept: configurar sesiones seguras: csrf
  - :yellow_circle: la cookie de sesión se maneja de forma segura (Habilitar HTTP y javascript en producción)

### Ordinario - martes 6 de junio del 2023

- :accept: seguridad en inicio de sesión

  - :accept: inicio de sesión del proyecto y registro de usuarios (bot de cada usuario)
  - :accept: Inicio de sesión multifactor telegram con OTP
  - :accept: limitar intentos
  - :accept: utilizar post para entrega de código
  - :accept: código de telegram aleatorios, expirar en 3 minutos, de un solo uso
  - :accept: si el token es incorrecto se invalida todo el proceso

- :accept: sandbox con docker

  - :accept: integrar todo el proyecto con docker
  - :accept: has uso de docker images y docker-compose para automatizar el despliegue
  - :accept: implementa seguridad (el contenedor no usa root)

- :yellow_circle: seguridad en el canal de comunicación
  - :accept: agregar soporte de HTTPS al ambiente de producción (hosting con Azure y let's encrypt)
  - :red_circle: agregar soporte de HTTPS al ambiente de producción (certificados autofirmados en entorno local)
