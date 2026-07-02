#!/usr/bin/env python3
"""
Cliente de Mercadopago para comunicaciones mTLS con Banco Santander
Simula solicitudes de transferencia bancaria
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
    """Adaptador personalizado para manejar mTLS con certificados cliente"""
    
    def __init__(self, cert_file, key_file, ca_file, **kwargs):
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file
        super().__init__(**kwargs)
    
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_verify_locations(cafile=self.ca_file)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_cert_chain(self.cert_file, self.key_file)
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

def create_mtls_session(cert_path, key_path, ca_path):
    """Crea una sesión con mTLS configurado"""
    session = requests.Session()
    # 1. Le decimos a la capa alta (requests) que use nuestra CA para validar
    session.verify = ca_path 
    # 2. Le decimos a la capa baja (urllib3) que inyecte las identidades
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
        "source_bank": "Mercadopago",
        "source_account": "MP-ACC-001",
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
        print(f"❌ Error SSL/mTLS: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"❌ Error en la solicitud: {e}")
        return None

def log_transaction(timestamp, status, transfer_id, amount, response_code):
    """Registra una transacción en logs"""
    log_entry = {
        "timestamp": timestamp,
        "client": "Mercadopago",
        "status": status,
        "transfer_id": transfer_id,
        "amount": amount,
        "response_code": response_code
    }
    print(json.dumps(log_entry, indent=2, default=str))

def main():
    # Configuración
    SERVER_URL = "https://localhost:8443"
    CERT_FILE = "./certs/mpago-cert.pem"
    KEY_FILE = "./certs/mpago-key.pem"
    CA_FILE = "../CABancoCentral/cacert.pem"
    
    print("=" * 60)
    print("🎯 Cliente Mercadopago - mTLS Bank Transfer")
    print("=" * 60)
    print(f"Conectando a: {SERVER_URL}")
    print(f"Certificados: {CERT_FILE}, {KEY_FILE}")
    print()
    
    try:
        # Crear sesión mTLS
        print("🔐 Configurando mTLS...")
        session = create_mtls_session(CERT_FILE, KEY_FILE, CA_FILE)
        
        # Verificar conectividad con health check
        print("✓ Verificando conectividad con el servidor...")
        health_response = session.get(f"{SERVER_URL}/health", timeout=5)
        if health_response.status_code == 200:
            print(f"✓ Servidor activo: {health_response.json()}")
        else:
            print(f"⚠️  Respuesta inesperada del servidor: {health_response.status_code}")
        
        print()
        print("=" * 60)
        print("📤 Enviando transferencias...")
        print("=" * 60)
        
        # Simular múltiples transferencias
        transfers = [
            {"amount": 1500.00, "destination_account": "ACC-SANTANDER-001", "description": "Pago de servicios"},
            {"amount": 2500.50, "destination_account": "ACC-SANTANDER-002", "description": "Remesa internacional"},
            {"amount": 800.00, "destination_account": "ACC-SANTANDER-003", "description": "Pago de deudas"},
        ]
        
        for i, transfer_info in enumerate(transfers, 1):
            timestamp = datetime.now().isoformat()
            
            # Crear solicitud
            transfer_data = create_transfer_request(
                amount=transfer_info["amount"],
                destination_account=transfer_info["destination_account"]
            )
            
            print(f"\n[{i}] {transfer_info['description']}")
            print(f"    Monto: ${transfer_info['amount']:.2f} USD")
            print(f"    Destinatario: {transfer_info['destination_account']}")
            
            # Enviar solicitud
            response = send_transfer(session, SERVER_URL, transfer_data)
            
            if response:
                status = "SUCCESS" if response.status_code == 200 else "FAILED"
                response_code = response.status_code
                
                if response.status_code == 200:
                    response_data = response.json()
                    transfer_id = response_data.get("transfer_id", "UNKNOWN")
                    print(f"    ✓ Respuesta: {response_data['message']}")
                    print(f"    ID Transacción: {transfer_id}")
                else:
                    transfer_id = "FAILED"
                    print(f"    ❌ Error: {response.text}")
                
                log_transaction(timestamp, status, transfer_id, transfer_info["amount"], response_code)
            else:
                log_transaction(timestamp, "FAILED", "N/A", transfer_info["amount"], 0)
            
            # Esperar entre transferencias
            if i < len(transfers):
                time.sleep(1)
        
        print()
        print("=" * 60)
        print("✓ Transferencias completadas")
        print("=" * 60)
        
    except Exception as e:
        print(f"❌ Error fatal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
