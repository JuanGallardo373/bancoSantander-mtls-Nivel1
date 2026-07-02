#!/bin/bash
set -e
mkdir -p certs
echo "Atacante generando su clave privada..."
openssl genrsa -out certs/atacante-key.pem 2048
echo ""
echo "Atacante generando certificado autofirmado..."
openssl req -new -x509 -key certs/atacante-key.pem -out certs/atacante-cert.pem \
	-days 365 -subj "/C=AR/ST=Buenos Aires/L=CABA/O=Hacker/CN=AtacanteMalisioso"
echo ""
echo "Certificado autofirmado creado:"
openssl x509 -in certs/atacante-cert.pem -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After|Public-Key"