#!/bin/bash 
set -e
mkdir -p certs
echo "Generando la clave privada para el cliente mercadopago..."
openssl genpkey -algorithm RSA -out certs/mpago-key.pem
echo "Generando la solicitud de firma (CSR)..."
openssl req -new -key certs/mpago-key.pem -out certs/mpago-req.pem -subj "/C=AR/ST=Buenos Aires/L=CABA/O=MercadoPago/CN=mercadopago"
echo "CSR de mercadopago creada"
