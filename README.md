# serverpulse

## Prácticas
### Parcial - jueves 1 de junio del 2023

- :accept: repositorio de código
	- :accept: github clonado
	- :accept: agregar compañeros
	- :accept: todos deben tener un clon del repo

- :red_circle: análisis de código estático
	- :accept: instalar sonarqube
	- :accept: scannear el proyecto
	- :accept: asignar tareas (autoasignarse tareas)
	- :red_circle: generar reporte de mitigaciones

- :accept: manejo de configuración sensible
	- :accept: crear sistema web
	- :accept: configurar para usar SMBD
	- :accept: separar configuraciones sensibles de settings en un archivo .env
	- :accept: hacer script para inicilizar el ambiente de depuración con seguridad
	- :accept: subir evidencias a Github

- :red_circle: almacenamiento de información sensible
	- :red_circle: registro de usuarios con políticas de contraseñas
	- :red_circle: hashing de contraseñas con salt y algoritmo seguro

- :red_circle: manejo seguro de sesiones web y cookies
	- :red_circle: configurar sesiones seguras: logout
	- :red_circle: configurar sesiones seguras: settings
	- :accept: configurar sesiones seguras: csrf
	- :red_circle: la cookie de sesión se maneja de forma segura


### Ordinario - martes 6 de junio del 2023

- :red_circle: seguridad en inicio de sesión
	- :accept: inicio de sesión del proyecto y registro de usuarios (bot de cada usuario)
	- :red_circle: Inicio de sesión multifactor telegram con OTP
	- :red_circle: limitar intentos
	- :red_circle: utilizar post para entrega de código
	- :red_circle: código de telegram aleatorios, expirar en 3 minutos, de un solo uso
	- :red_circle: si el token es incorrecto se invalida todo el proceso

- :red_circle: sandbox con docker
	- :red_circle: integrar todo el proyecto con docker
	- :red_circle: has uso de docker images y docker-compose para automatizar el despliegue
	- :red_circle: implementa seguridad (el contenedor no usa root)

- :red_circle: seguridad en el canal de comunicación
	- :accept: agregar soporte de HTTPS al ambiente de producción (hosting con Azure y let's encrypt)
	- :red_circle: agregar soporte de HTTPS al ambiente de producción (certificados autofirmados en entorno local)

