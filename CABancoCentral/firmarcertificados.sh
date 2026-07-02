#!/bin/bash
set -e
echo "Firmando certificados para el servidor del Banco Santander y los bancos y Fintech clientes..."
openssl ca -config ca.conf -extensions server_extensions \
    -out ../servidor-banco/certs/santander-cert.pem -infiles ../servidor-banco/certs/santander-req.pem
openssl ca -config ca.conf -extensions client_extensions \
    -out ../cliente-mercadopago/certs/mpago-cert.pem -infiles ../cliente-mercadopago/certs/mpago-req.pem
openssl ca -config ca.conf -extensions client_extensions \
    -out ../cliente-bancobbva/certs/bbva-cert.pem -infiles ../cliente-bancobbva/certs/bbva-req.pem
echo "Certificados firmados por el Banco Central (CA)"
