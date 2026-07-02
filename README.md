
# 🏦 Banco Santander mTLS - Laboratorio de Seguridad

Simulación de servidor bancario con comunicaciones **mTLS (Mutual TLS)** bidireccionales, detección de anomalías en handshakes y análisis de seguridad con **LLM local (Ollama)**.

## 📋 Descripción del Proyecto

Este proyecto implementa:

1. **Servidor Go** - Banco Santander con mTLS obligatorio
   - Endpoint `/transfer` para transferencias bancarias
   - Endpoint `/health` para verificar estado
   - Logging de anomalías en JSON
   - Validación de certificados cliente

2. **Clientes Python** - BBVA y Mercadopago
   - Comunicación mTLS con certificados cliente propios
   - Simulación de transferencias bancarias
   - Logging de transacciones

3. **Analizador de IA** - LLM local (Ollama)
   - Análisis automático de logs de anomalías
   - Detección de patrones de ataque
   - Notificaciones de seguridad al administrador
   - Clasificación de riesgos

## 🏗️ Estructura del Proyecto


## 🚀 Requisitos Previos

### Sistema
- **Go** 1.19+
     sudo apt install golang-go
- **Python** 3.8+
     sudo apt install -y python3 python3-pip python3-dev python3-venv libssl-dev libffi-dev && \
     pip3 install --upgrade pip
- **Ollama** (para análisis con LLM)
     Linux: curl -fsSL https://ollama.com/install.sh | sh
     Windows: https://ollama.com/download/windows

### Instalación
# Clonar repositorio
git clone https://github.com/JuanGallardo373/bancoSantander-mtls.git
cd bancoSantander-mtls

# Instalar y descargar modelo Ollama
ollama pull llama3

🚀 Cómo Usarlo:
Terminal 1 - Ollama:
ollama serve

Terminal 2 - Servidor:
cd servidor-banco
go run main.go

Terminal 3 - Analizador (CONTINUO):
cd analista-ia
python3 llm_analyzer.py --interval 10  # Verifica cada 10 seg
python3 llm_analyzer.py --ollama-url http://X.X.X.X:11434  #Modificar URL

Terminal 4 - Cliente/Atacante:
cd cliente-atacante
python3 atacante.py

🛡️ Características de Seguridad
✅ mTLS Obligatorio

Requiere certificado cliente válido
Valida fecha de expiración
Verifica firma de CA
✅ Logging Detallado

Todos los errores de handshake registrados
Formato JSON para parsing automático
Timestamps precisos
✅ Análisis Inteligente

LLM detecta patrones de ataque
Clasificación automática de riesgos
Alertas contextualizadas
✅ Notificaciones

Alertas para administrador en tiempo real
Recomendaciones de acción
Severidad clasificada
🔧 Troubleshooting
Error: "Error cargando CA certificate"
Code
Solución: Verificar que ca-cert.pem existe en servidor-banco/certs/
Error: "SSL: CERTIFICATE_VERIFY_FAILED"
Code
Solución: Asegurar que el certificado cliente es válido y está firmado por la CA
Error: "No se puede conectar a Ollama"
Code
Solución: 
1. Instalar Ollama
2. Ejecutar: ollama serve
3. Descargar modelo: ollama pull llama2

📝 Notas de Desarrollo
Agregar nuevo cliente
Generar certificado con autoridad CA
Crear script Python en cliente-{banco}/
Usar mismo patrón de MTLSAdapter
Actualizar documentación
Modificar endpoint
Editar función handler en main.go
Agregar validaciones necesarias
Loguear anomalías detectadas
Recompilar: go run main.go
Personalizar análisis LLM
Modificar prompt en analyze_with_llm()
Ajustar temperatura (0-1) para variabilidad
Cambiar modelo en parámetro --model
Cambiar URL de Ollama en parámetro --ollama-url http://x.x.x.x:14434
Observar logs generados por el LLM con los comandos:
   *Observar en una segunda terminal en vivo: tail -f ../logs/anomalies.jsonl | jq
   cat ../logs/analysis.jsonl | jq -r '.llm_analysis'
   cat ../logs/admin_alerts.log

📚 Referencias
Go TLS Documentation
Python Requests SSL
Ollama Documentation
mTLS Concepts
📄 Licencia
Este proyecto es parte de un laboratorio educativo de seguridad.

👤 Autor
Juan Gallardo - @JuanGallardo373
