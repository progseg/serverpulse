import getpass
import subprocess
import os

password = getpass.getpass(
    'Ingresa la contraseña para desencriptar el archivo secrets.env.gpg: ')

try:
    gpg_cmd = f'gpg --decrypt --batch --passphrase-fd 0 secrets.env.gpg'
    env_data = subprocess.check_output(
        gpg_cmd, shell=True, input=password.encode())
except Exception:
    print('Contraseña incorrecta')
    exit(1)

if env_data is None:
    print('El archivo de variables de entorno parece estar vacio, nada que hacer')
    exit(1)

for env in env_data.decode().splitlines():
    key, value = env.split('=', 1)
    os.environ[key] = value
    print(f'{key} = {os.environ.get(key)}')

#try:
#    exec_terminal_net = subprocess.call([
#        'docker',
#        'network',
#        'create',
#        '-d',
#        'bridge',
#        '--subnet',
#        '192.167.54.0/24',
#        '--gateway',
#        '192.167.54.1',
#        'terminal'
#        ]
#    )
#except Exception:
#    print('Error al crear la red virtual terminal')
#    exit(1)

try:
    exec_docker_compose = subprocess.call(['docker', 'compose', 'up'])
except Exception:
    print('El ambiente no pudo inicializarse, error inesperado')
    subprocess.call(['docker', 'compose', 'kill'])
    exit(1)

print('Ambiente inicializado')
