#!/usr/bin/env python3
"""
Analizador de Anomalías mTLS usando LLM local (Ollama)
Detecta patrones de ataque y anomalías en los logs de handshakes mTLS
Análisis CONTINUO en tiempo real
"""

import json
import requests
import sys
from datetime import datetime, timedelta
from pathlib import Path
import time
import threading

class MTLSAnomalyAnalyzer:
    """Analizador de anomalías mTLS con LLM local"""
    
    def __init__(self, ollama_url="http://localhost:11434", model="llama3"):
        """
        Inicializa el analizador
        
        Args:
            ollama_url: URL del servidor Ollama
            model: Modelo LLM a usar
        """
        self.ollama_url = ollama_url
        self.model = model
        self.log_file = "../logs/anomalies.jsonl"
        self.analysis_file = "../logs/analysis.jsonl"
        self.last_processed = 0  # Último índice procesado
        self.anomalies_buffer = []  # Buffer para análisis
    
    def check_ollama_availability(self):
        """Verifica si Ollama está disponible"""
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            return response.status_code == 200
        except requests.RequestException:
            return False
    
    def read_new_logs(self):
        """Lee solo los logs nuevos desde la última lectura"""
        new_anomalies = []
        
        if not Path(self.log_file).exists():
            return new_anomalies
        
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
                
                # Procesar solo líneas nuevas
                for i in range(self.last_processed, len(lines)):
                    line = lines[i].strip()
                    if line:
                        try:
                            log_entry = json.loads(line)
                            new_anomalies.append(log_entry)
                        except json.JSONDecodeError:
                            continue
                
                # Actualizar índice
                self.last_processed = len(lines)
        
        except Exception as e:
            print(f"❌ Error leyendo logs: {e}")
        
        return new_anomalies
    
    def format_anomalies_for_analysis(self, anomalies):
        """Formatea las anomalías para análisis por LLM"""
        if not anomalies:
            return "Sin anomalías nuevas detectadas."
        
        formatted = "ANOMALÍAS DETECTADAS EN LOGS mTLS (ANÁLISIS CONTINUO):\n\n"
        for i, anomaly in enumerate(anomalies, 1):
            formatted += f"{i}. Timestamp: {anomaly.get('timestamp')}\n"
            formatted += f"   Cliente: {anomaly.get('client_name', 'Desconocido')}\n"
            formatted += f"   IP: {anomaly.get('client_ip', 'N/A')}\n"
            formatted += f"   Tipo: {anomaly.get('event_type', 'N/A')}\n"
            formatted += f"   Certificado Expirado: {anomaly.get('is_expired', False)}\n"
            formatted += f"   Autofirmado: {anomaly.get('is_self_signed', False)}\n"
            formatted += f"   Error Handshake: {anomaly.get('handshake_error', False)}\n"
            formatted += f"   Mensaje: {anomaly.get('error_message', 'N/A')}\n"
            
            if anomaly.get('cert_chain'):
                formatted += f"   Cadena de certificados:\n"
                for cert_info in anomaly.get('cert_chain', []):
                    formatted += f"      - {cert_info}\n"
            
            formatted += "\n"
        
        return formatted
    
    def analyze_with_llm(self, anomalies_text):
        prompt = f"""[INST] Eres un agente de ciberseguridad financiera en espacio de usuario.
Analiza la ráfaga de logs mTLS adjunta. Responde de forma puramente técnica y ultra-concisa.
ESTRICTAMENTE prohibido introducir párrafos introductorios, saludos, notas o prosa explicativa.

Logs a procesar:
{anomalies_text}

Tu salida debe seguir EXACTAMENTE esta estructura de texto plano:
Clasificación de riesgo: [CRÍTICO|ALTO|MEDIO|BAJO]
Tipo de ataque: [MITM|Suplantación|Fuerza Bruta|Escaneo de Vulnerabilidades|Ninguno]
Bloquear IP: [SI|NO] - [Breve razón en pocas palabras]
Notificar Admin: [SI|NO]

* **Identificación por Evento:**
  - **Evento [ID o IP]:** [Interpretación técnica de lo que intentó hacer y por qué falló mTLS]
[/INST]"""

        start_time = time.time()
        try:
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.2  # Más bajo para respuestas más deterministas
                },
                timeout=120  # Timeout más largo para análisis complejos
            )
            end_time = time.time()
            llm_duration_seconds = end_time - start_time
            print(f"⏱️ Tiempo de procesamiento de Ollama: {llm_duration_seconds:.2f} segundos.")
            
            if response.status_code == 200:
                return response.json().get('response', '')
            else:
                return f"Error en LLM: {response.status_code} - {response.text}"
        except requests.exceptions.Timeout:
            return "Error: Timeout agotado. La IA tardó demasiado en responder (VM con bajos recursos)."        
        except requests.RequestException as e:
            return f"No se pudo conectar a Ollama: {e}"
    
    def save_analysis(self, anomalies, analysis):
        """Guarda el análisis en archivo JSON"""
        analysis_entry = {
            "timestamp": datetime.now().isoformat(),
            "anomalies_count": len(anomalies),
            "anomalies": anomalies,
            "llm_analysis": analysis,
            "analysis_mode": "continuous"
        }
        
        # Crear directorio si no existe
        Path("../logs").mkdir(parents=True, exist_ok=True)
        
        try:
            with open(self.analysis_file, 'a') as f:
                f.write(json.dumps(analysis_entry) + '\n')
        except Exception as e:
            print(f"❌ Error guardando análisis: {e}")
    
    def check_alert_conditions(self, anomalies, analysis):
        """Verifica si se debe generar alerta al administrador basándose en la salida estructurada del LLM"""
        alert = {
            "should_alert": False,
            "reason": "",
            "severity": "LOW"
        }
    
        analysis_upper = analysis.upper()
        anomaly_count = len(anomalies)
    
        is_critical_risk = "Clasificación de riesgo: CRÍTICO" in analysis_upper or "Clasificación de riesgo: ALTO" in analysis_upper
        should_block = "Bloquear IP: SI" in analysis_upper
        should_notify = "Notificar Admin: SI" in analysis_upper
    
        if should_notify or is_critical_risk or should_block:
            alert["should_alert"] = True
        
        if anomaly_count >= 2 and is_critical_risk:
            alert["severity"] = "CRÍTICO"
            alert["reason"] = f"Múltiples anomalías críticas detectadas ({anomaly_count}) y ratificadas por el LLM"
        elif "RISK: CRÍTICO" in analysis_upper or should_block:
            alert["severity"] = "CRÍTICO"
            alert["reason"] = "El agente LLM determinó riesgo crítico con requerimiento de bloqueo de IP"
        else:
            alert["severity"] = "ALTO"
            alert["reason"] = "Anomalía de seguridad mitigada en transporte que requiere auditoría"
            
        return alert
    
    def send_admin_notification(self, alert, analysis, anomalies):
        """Envía notificación al administrador"""
        if not alert["should_alert"]:
            return
        
        notification = f"""
╔═══════════════════════════════════════════════════════════════╗
║      ⚠️  ALERTA DE SEGURIDAD mTLS - BANCO SANTANDER          ║
║              (ANÁLISIS CONTINUO EN TIEMPO REAL)              ║
╚═══════════════════════════════════════════════════════════════╝

SEVERIDAD: {alert['severity']}
MOTIVO: {alert['reason']}
TIMESTAMP: {datetime.now().isoformat()}
ANOMALÍAS DETECTADAS: {len(anomalies)}

═══════════════════════════════════════════════════════════════
DETALLES DE ANOMALÍAS:
═══════════════════════════════════════════════════════════════
"""
        
        for i, anomaly in enumerate(anomalies, 1):
            notification += f"\n[{i}] IP: {anomaly.get('client_ip')} | Cliente: {anomaly.get('client_name')}\n"
            notification += f"    Evento: {anomaly.get('event_type')}\n"
            notification += f"    Mensaje: {anomaly.get('error_message')}\n"
        
        notification += f"""
═══════════════════════════════════════════════════════════════
ANÁLISIS DEL LLM:
═══════════════════════════════════════════════════════════════
{analysis}

═══════════════════════════════════════════════════════════════
ACCIÓN REQUERIDA:
═══════════════════════════════════════════════════════════════
1. Revisar inmediatamente los logs: ../logs/anomalies.jsonl
2. Implementar recomendaciones del LLM
3. Considerar bloqueo de IPs sospechosas
4. Activar protocolos de incidente de seguridad
5. Contactar al equipo de ciberseguridad

═══════════════════════════════════════════════════════════════
"""
        
        print(notification)
        
        # Guardar notificación en archivo
        try:
            with open("../logs/admin_alerts.log", 'a') as f:
                f.write(notification)
        except Exception as e:
            print(f"❌ Error guardando alerta: {e}")
    
    def print_status(self, anomalies_count):
        """Imprime estado del monitor"""
        status = f"[{datetime.now().strftime('%H:%M:%S')}] "
        if anomalies_count > 0:
            status += f"🔴 {anomalies_count} ANOMALÍA(S) NUEVA(S) DETECTADA(S)"
        else:
            status += "🟢 Sin anomalías nuevas"
        
        print(status)
    
    def run_continuous_analysis(self, check_interval=10):
        """Ejecuta análisis continuo en tiempo real"""
        print("\n" + "="*70)
        print("🔍 ANALIZADOR DE ANOMALÍAS mTLS - MODO CONTINUO")
        print("="*70)
        
        # Verificar disponibilidad de Ollama
        print(f"\n🔌 Verificando conexión a Ollama ({self.ollama_url})...")
        if not self.check_ollama_availability():
            print(f"❌ Ollama no disponible en {self.ollama_url}")
            print("   Soluciones:")
            print("   1. Instalar Ollama: https://ollama.ai")
            print("   2. En otra terminal ejecutar: ollama serve")
            print("   3. Descargar modelo: ollama pull llama2")
            print("   4. Reintentar este script")
            return
        
        print(f"✓ Ollama conectado. Modelo: {self.model}")
        print(f"✓ Intervalo de verificación: {check_interval} segundos")
        print(f"✓ Leyendo logs desde: {self.log_file}")
        print()
        
        print("=" * 70)
        print("⏳ Iniciando monitoreo continuo...")
        print("   Presiona Ctrl+C para detener")
        print("=" * 70)
        print()
        
        analysis_count = 0
        try:
            while True:
                # Verificar nuevas anomalías
                new_anomalies = self.read_new_logs()
                self.print_status(len(new_anomalies))
                
                if new_anomalies:
                    analysis_count += 1
                    
                    print(f"\n{'─'*70}")
                    print(f"📊 ANÁLISIS #{analysis_count} - {len(new_anomalies)} anomalía(s)")
                    print(f"{'─'*70}")
                    
                    # Formatear anomalías
                    anomalies_text = self.format_anomalies_for_analysis(new_anomalies)
                    
                    # Mostrar anomalías detectadas
                    print("\n📋 Anomalías detectadas:")
                    for i, anom in enumerate(new_anomalies, 1):
                        print(f"   [{i}] {anom.get('event_type')} - IP: {anom.get('client_ip')} - {anom.get('error_message', 'N/A')[:50]}")
                    
                    # Análisis con LLM
                    print(f"\n🤖 Analizando con LLM ({self.model})...")
                    analysis = self.analyze_with_llm(anomalies_text)
                    
                    # Guardar análisis
                    self.save_analysis(new_anomalies, analysis)
                    
                    # Verificar condiciones de alerta
                    alert = self.check_alert_conditions(new_anomalies, analysis)
                    
                    # Enviar notificación si es necesario
                    if alert["should_alert"]:
                        print()
                        self.send_admin_notification(alert, analysis, new_anomalies)
                    else:
                        print("\n✓ Análisis completado. No se requiere alerta inmediata.")
                    
                    print(f"\n{'─'*70}\n")
                
                # Esperar antes de la siguiente verificación
                time.sleep(check_interval)
        
        except KeyboardInterrupt:
            print("\n\n" + "="*70)
            print(f"⏹️  Monitoreo detenido por el usuario")
            print(f"   Total de análisis realizados: {analysis_count}")
            print("="*70)
            sys.exit(0)
        
        except Exception as e:
            print(f"\n❌ Error en monitoreo: {e}")
            sys.exit(1)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Analizador de anomalías mTLS con LLM local - Modo Continuo"
    )
    parser.add_argument(
        "--ollama-url",
        default="http://localhost:11434",
        help="URL del servidor Ollama (default: http://localhost:11434)"
    )
    parser.add_argument(
        "--model",
        default="llama3",
        help="Modelo LLM a usar (default: llama3)"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=10,
        help="Intervalo de verificación en segundos (default: 10)"
    )
    
    args = parser.parse_args()
    
    analyzer = MTLSAnomalyAnalyzer(
        ollama_url=args.ollama_url,
        model=args.model
    )
    
    analyzer.run_continuous_analysis(check_interval=args.interval)

if __name__ == "__main__":
    main()


