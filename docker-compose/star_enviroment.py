import getpass
import subprocess
import os

password = getpass.getpass(
    'Ingresa la contraseña para desencriptar el archivo secrets.env.gpg: ')

gpg_cmd = f'gpg --decrypt --batch --passphrase-fd 0 secrets.env.gpg'
env_data = subprocess.check_output(
    gpg_cmd, shell=True, input=password.encode())

if env_data is not None:
    for env in env_data.decode().splitlines():
        print(env)
        key, value = env.split('=', 1)
        os.environ[key] = value

    if subprocess.call(['docker', 'compose', 'up', '-d']) == 0:
        print('Ambiente inicializado')
        exit(0)

    print('El ambiente no pudo inicializarse, error inesperado')
    subprocess.call(['docker', 'compose', 'kill'])
    exit(1)

print('El archivo no se pudo desencriptar, revisa tu contraseña')
exit(1)
