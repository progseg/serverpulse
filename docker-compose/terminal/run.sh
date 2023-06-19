#!/bin/bash

su -c "ttyd --writable -c $USER_TERMINAL:$PASSWORD_TERMINAL bash" limitado
#su -c "ttyd --ssl --ssl-cert /etc/certs/cert.crt --ssl-key /etc/certs/key.pem --writable -c $USER_TERMINAL:$PASSWORD_TERMINAL bash" limitado