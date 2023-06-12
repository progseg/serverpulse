# base image
FROM python:3.10-bullseye

# update and install environment dependencies
RUN apt update
RUN apt full-upgrade -y
RUN pip install gunicorn

# create user exec
RUN useradd -M -s /usr/bin/nologin serverpulse

# app port
EXPOSE 8000

# Set workon dir
WORKDIR /app

# persistent storage
VOLUME /app

# install internal dependencies
COPY ./requeriments.txt .
RUN pip install -r requeriments.txt

# change owner and permissions of volume
COPY ./setup_serverpulse.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/setup_serverpulse.sh


# set service user
USER serverpulse

# run application
CMD ["/bin/sh", "-c", "/usr/local/bin/setup_serverpulse.sh && gunicorn serverPulse.wsgi:application --bind 0.0.0.0:8000"]
