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

try:
    exec_docker_compose = subprocess.call(['docker', 'compose', 'up', '-d'])
    print('Ambiente inicializado')
    exit(0)
except Exception as e:
    print(f"El ambiente no pudo inicializarse, error inesperado: {e}")
    subprocess.call(['docker', 'compose', 'kill'])
    exit(1)