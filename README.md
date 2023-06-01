# serverpulse

## Prácticas
### Parcial - jueves 1 de junio del 2023

- [X] repositorio de código
	- [X] github clonado
	- [X] agregar compañeros
	- [X] todos deben tener un clon del repo

- [ ] análisis de código estático
	- [X] instalar sonarqube
	- [X] scannear el proyecto
	- [X] asignar tareas (autoasignarse tareas)
	- [ ] generar reporte de mitigaciones

- [X] manejo de configuración sensible
	- [x] crear sistema web
	- [X] configurar para usar SMBD
	- [X] separar configuraciones sensibles de settings en un archivo .env
	- [X] hacer script para inicilizar el ambiente de depuración con seguridad
	- [X] subir evidencias a Github

- [ ] almacenamiento de información sensible
	- [] registro de usuarios con políticas de contraseñas
	- [ ] hashing de contraseñas con salt y algoritmo seguro

- [ ] manejo seguro de sesiones web y cookies
	- [ ] configurar sesiones seguras: logout
	- [ ] configurar sesiones seguras: settings
	- [X] configurar sesiones seguras: csrf
	- [ ] la cookie de sesión se maneja de forma segura


### Ordinario - martes 6 de junio del 2023

- [ ] seguridad en inicio de sesión
	- [X] inicio de sesión del proyecto y registro de usuarios (bot de cada usuario)
	- [] Inicio de sesión multifactor telegram con OTP
	- [ ] limitar intentos
	- [ ] utilizar post para entrega de código
	- [ ] código de telegram aleatorios, expirar en 3 minutos, de un solo uso
	- [ ] si el token es incorrecto se invalida todo el proceso

- [ ] sandbox con docker
	- [ ] integrar todo el proyecto con docker
	- [ ] has uso de docker images y docker-compose para automatizar el despliegue
	- [ ] implementa seguridad (el contenedor no usa root)

- [] seguridad en el canal de comunicación
	- [X] agregar soporte de HTTPS al ambiente de producción (hosting con Azure y let's encrypt)
	- [] agregar soporte de HTTPS al ambiente de producción (certificados autofirmados en entorno local)

