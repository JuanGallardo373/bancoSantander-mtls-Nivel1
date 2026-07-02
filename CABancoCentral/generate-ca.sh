#!/bin/bash
set -e
mkdir -p private newcerts
touch index.txt
echo 1000 > serial
echo "Generando clave privada y certificado del Banco Central (CA)..."
openssl req -new -x509 -days 3650 -extensions v3_ca -keyout private/cakey.pem \
	-out cacert.pem -config ca.conf -subj "/C=AR/ST=Buenos Aires/L=CABA/CN=BancoCentralCA" 
echo "Generado correctamente"
echo ""
echo "Información del certificado:"
openssl x509 -in cacert.pem -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After|Public-Key"
