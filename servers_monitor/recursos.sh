#!/bin/bash

while true; do
	#Obtner el uso de la cpu
	cpu_usage=$(mpstat -u | awk '{print $12}' | tail -n1 | tr ',' '.' | awk '{print ($1 -100) * -1}' | awk '{print $1"%"}')

	#Obtener detalles del procesador
	processor_details=$(cpu_usage=$(free -m | grep Mem | awk '{print $3/$2 * 100}' | head -c 4 | awk '{print $1"%"}'))

	#Obtener el espacio en el disco
	disk_usage=$(df -t ext4 -h | awk '{print $5}' | tail -n1)

	curl -X POST -d "cpu_usage=$cpu_usage&processor_details=$processor_details&disk_usage=$disk_usage" http://10.0.2.61:8000/monitor_data/

	sleep 5

done
