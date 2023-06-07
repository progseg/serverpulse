#Ejecutar como root

service_path="/etc/init.d/agent.service"

service_path="test.sh"

opcion='$1'
service_code="\n
#!/bin/sh\n
case $opcion in\n
\tstart)\n
\t\techo 'test'\n
\t\t# Ingresar codigo de validacion hacia el server principal\n
\t;;\n
\tstop)\n
\t\t# Ingresar codigo de cierre de conexion hacia el server principal\n
\t;;\n
\trestart)\n
\t\t# Ingresar codigo de cierre de conexion hacia el server principal\n
\t;;\n
esac\n
"
echo $service_code > $service_path

chmod +x $service_path

ln -s $service_path /etc/rc3.d/S99agemt
ln -s $service_path /etc/rc5.d/S99agemt
ln -s $service_path /etc/rc6.d/K01agent
ln -s $service_path /etc/rc0.d/K01agent

script_path="/root/.monitoring"
if [ ! -d $script_path ];then
    mkdir $script_path
fi
script_path="$script_path/send_data_monitoring.sh"
if [ -f $script_path ];then
    rm $script_path
fi
echo "#!/bin/sh" >> $script_path
tmp=`echo "cGVyY2VudF9tZW1vcnk9YGZyZWUgLW0gfCBncmVwIE1lbSB8IGF3ayAne3ByaW50ICQzLyQyICogMTAwfScgfCBoZWFkIC1jIDQgfCBhd2sgJ3twcmludCAkMSIlIn0nYA==" | base64 -d`
echo $tmp >> $script_path
tmp=`echo "cGVyY2VudF9jcHU9YG1wc3RhdCAtdSB8IGF3ayAne3ByaW50ICQxMn0nIHwgdGFpbCAtbjEgfCB0ciAnLCcgJy4nIHwgYXdrICd7cHJpbnQgKCQxIC0xMDApICogLTF9JyB8IGF3ayAne3ByaW50ICQxIiUifSdg" | base64 -d`
echo $tmp >> $script_path
tmp=`echo "cGVyY2VudF9kaXNjX3VzZT1gZGYgLXQgZXh0NCAtaCB8IGF3ayAne3ByaW50ICQ1fScgfCB0YWlsIC1uMWA=" | base64 -d`
echo $tmp >> $script_path
script_code="
#Codigo de envio de estado alive a server principal
#Envio de la informacion
"
echo $script_code >> $script_path

chmod +x $script_path
# echo "#* * * * * #Codigo de envio de estado alive a server principal" >> /etc/crontab
echo "* * * * * $script_path" >> /etc/crontab

# script_path
# percent_memory=`free -m | grep Mem | awk '{print $3/$2 * 100}' | head -c 4 | awk '{print $1"%"}'`\n
# percent_cpu=`mpstat -u | awk '{print $12}' | tail -n1 | tr ',' '.' | awk '{print ($1 -100) * -1}' | awk '{print $1"%"}'`\n
# percent_disc_use=`df -t ext4 -h | awk '{print $5}' | tail -n1`\n