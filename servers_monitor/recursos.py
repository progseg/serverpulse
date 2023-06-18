import psutil
import requests
import time
import json

url = 'http://192.168.1.85:8000/monitor_data/'

while True:
    memory_percent = psutil.virtual_memory().percent
    cpu_percent = psutil.cpu_percent()
    disk_percent = psutil.disk_usage('/').percent

    params = {
        'memory_percent': memory_percent,
        'cpu_percent': cpu_percent,
        'disk_percent': disk_percent
    }

    response = requests.get(url, params=params)

    #response = requests.get(url, params=params)
    if response.status_code == 200:
        print('Datos enviados correctamente')
        print(response.text)
    else:
        print('Error al enviar los datos')

    # Espera 1 segundo antes de enviar la siguiente solicitud
#    time.sleep(1)
