#Ejecutar como root

# Creacion del script agente para inicio y apagado del equipo

echo "#!/bin/sh" >> /etc/init.d/agent.service
echo 'case "$1" in' >> /etc/init.d/agent.service
echo "start)" >> /etc/init.d/agent.service
echo curl -X GET 10.0.2.61:8000/listarServidores >> /etc/init.d/agent.service
echo ";;" >> /etc/init.d/agent.service
echo "stop)" >> /etc/init.d/agent.service
echo curl -X GET 10.0.2.61:8000/apagarServidor >> /etc/init.d/agent.service
echo ";;" >> /etc/init.d/agent.service
echo "restart)" >> /etc/init.d/agent.service
echo curl -X GET 10.0.2.61:8000/apagarServidor >> /etc/init.d/agent.service
echo ";;" >> /etc/init.d/agent.service
echo "esac" >> /etc/init.d/agent.service

#Asignacion de permisos

chmod u+x /etc/init.d/agent.service

# Creacion de los demonios en entorno grafico (5) y entorno de CLI (3) para inicio, apagado (0) y reinicio (6) del equipo

ln -s /etc/init.d/agent.service /etc/rc3.d/S99agent
ln -s /etc/init.d/agent.service /etc/rc5.d/S99agent
ln -s /etc/init.d/agent.service /etc/rc6.d/K01agent
ln -s /etc/init.d/agent.service /etc/rc0.d/K01agent
