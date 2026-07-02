#!/usr/bin/env python3
"""
Cliente Atacante - Intento de robo de certificado sin clave privada
Simula solicitudes de transferencia bancaria con mismatch de llaves
"""

import ssl
import requests
import json
import time
import sys
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

class MTLSAdapter(HTTPAdapter):
    def __init__(self, cert_file, key_file, ca_file, **kwargs):
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file
        super().__init__(**kwargs)
    
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        
        # Configuración estricta de seguridad
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_verify_locations(cafile=self.ca_file)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        
        # Simulación del Mismatch: El atacante intenta ensamblar la identidad robada
        try:
            ctx.load_cert_chain(self.cert_file, self.key_file)
        except ssl.SSLError as e:
            print(f"\n🛑 [BLOQUEO LOCAL OS] Fallo de integridad criptográfica:")
            print(f"   Error: {e}")
            print("   Motivo: OpenSSL detectó que la clave privada generada por el atacante")
            print("   no coincide con la clave pública del certificado robado de Mercado Pago.")
            print("   Se intentará conectar de todas formas sin identidad...\n")
            
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

def create_mtls_session(cert_path, key_path, ca_path):
    """Crea una sesión con mTLS configurado y validación global"""
    session = requests.Session()
    session.verify = ca_path
    
    adapter = MTLSAdapter(
        cert_file=cert_path,
        key_file=key_path,
        ca_file=ca_path,
        pool_connections=10,
        pool_maxsize=10
    )
    session.mount('https://', adapter)
    return session

def create_transfer_request(amount, destination_account, destination_bank="Santander"):
    """Crea una solicitud de transferencia"""
    return {
        "source_bank": "Lemoncash",
        "source_account": "LC-ACC-001",
        "destination_bank": destination_bank,
        "destination_account": destination_account,
        "amount": amount,
        "currency": "USD"
    }

def send_transfer(session, server_url, transfer_data, timeout=10):
    """Envía una solicitud de transferencia al servidor"""
    try:
        response = session.post(
            f"{server_url}/transfer",
            json=transfer_data,
            timeout=timeout
        )
        return response
    except requests.exceptions.SSLError as e:
        print(f"❌ Error SSL/mTLS (Rechazo del Banco): {str(e)[:100]}...")
        return None
    except requests.exceptions.RequestException as e:
        print(f"❌ Error de red: {e}")
        return None

def main():
    # Configuración del ataque
    SERVER_URL = "https://localhost:8443"
    CERT_FILE = "../cliente-mercadopago/certs/mpago-cert.pem" # Certificado robado válido
    KEY_FILE = "./certs/atacante-key.pem"                     # Clave privada falsa/propia
    CA_FILE = "../CABancoCentral/cacert.pem"
    
    print("=" * 60)
    print("🎯 Cliente Atacante - Robo Parcial de Identidad (Mismatch)")
    print("=" * 60)
    print(f"Conectando a: {SERVER_URL}")
    print(f"Certificado: {CERT_FILE}")
    print(f"Llave Priv.: {KEY_FILE}")
    print()
    
    try:
        print("🔐 Ensamblando identidad mTLS...")
        session = create_mtls_session(CERT_FILE, KEY_FILE, CA_FILE)
    
        print()
        print("=" * 60)
        print("📤 Ejecutando ataques de inyección de transferencias...")
        print("=" * 60)
        
        transfers = [
            {"amount": 150000.00, "destination_account": "ACC-SANTANDER-001", "description": "Pago de servicios falso"},
            {"amount": 250000.50, "destination_account": "ACC-SANTANDER-002", "description": "Remesa internacional fraudulenta"},
        ]
        
        for i, transfer_info in enumerate(transfers, 1):
            transfer_data = create_transfer_request(
                amount=transfer_info["amount"],
                destination_account=transfer_info["destination_account"]
            )
            
            print(f"\n[{i}] {transfer_info['description']}")
            print(f"    Monto: ${transfer_info['amount']:.2f} USD")
            
            response = send_transfer(session, SERVER_URL, transfer_data)
            
            if response and response.status_code == 200:
                print(f"    🚨 ¡ÉXITO CRÍTICO! {response.json()['message']}")
            else:
                print(f"    🛡️ Ataque mitigado. No se inyectaron fondos.")
            
            if i < len(transfers):
                time.sleep(1)
        
    except Exception as e:
        print(f"❌ Error fatal en el simulador: {e}")

if __name__ == "__main__":
    main()
