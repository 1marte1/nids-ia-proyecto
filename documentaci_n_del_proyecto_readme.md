# 🛡️ NIDS-IA: Sistema de Detección de Intrusiones en Redes Basado en Aprendizaje Automático

Prototipo funcional de un **Sistema de Detección de Intrusiones en Redes (NIDS)** en tiempo real impulsado por Inteligencia Artificial (**Random Forest**). El sistema captura tráfico de red en Capa 2, reconstruye flujos bidireccionales por tupla de 5 elementos, extrae **77 características estadísticas** compatibles con el estándar **CIC-IDS2017** y clasifica las conexiones en vivo mediante un panel web interactivo en **Streamlit**.

**Autor:** Iván Cruz Lafarga  
**Institución:** Instituto Tecnológico de Tijuana (ITT)  
**Contacto:** l22211548@tectijuana.edu.mx  

---

## 🏗️ Arquitectura del Proyecto

El flujo de procesamiento opera en cuatro capas desacopladas:

```text
[Tarjeta de Red / Npcap] 
       │
       ▼
[Captura de Paquetes Scapy (sniff)] 
       │
       ▼
[Agrupación por 5-Tupla y Cálculo de 77 Métricas (NIDSEngine)] 
       │
       ▼
[Inferencia Random Forest (nids_random_forest.joblib)] 
       │
       ▼
[Dashboard Web Streamlit (KPIs, Alertas, Gráficas y Exportación CSV)]
```

### Estructura del Repositorio

```text
nids-ia-proyecto/
├── data/
│   └── DDoS-Friday-no-metadata.parquet   # Dataset CIC-IDS2017 depurado (77 features)
├── models/
│   └── nids_random_forest.joblib         # Clasificador Random Forest entrenado y serializado
├── notebooks/                            # Libretas Jupyter de análisis exploratorio (EDA) y entrenamiento
├── src/
│   ├── sniffer.py                        # Prueba inicial de captura IPv4/TCP/UDP en Capa 2
│   ├── flow_sniffer.py                   # Reconstructor intermedio de flujos bidireccionales
│   ├── nids_engine.py                    # Motor principal de captura, vectorización e inferencia
│   ├── dashboard.py                      # Interfaz gráfica en Streamlit + módulo Trace Replay
│   └── simulador_ataque.py               # Utilidad de laboratorio para inyección controlada en Capa 2
├── .gitignore
├── requirements.txt
└── README.md
```

---

## ⚙️ Requisitos del Sistema

* **Sistema Operativo:** Windows 10 / 11 (con privilegios de **Administrador** para lectura de sockets en Capa 2).
* **Python:** Versión `3.12.x` (probado en `Python 3.12.10`).
* **Controlador de Red:** [Npcap](https://npcap.com/) instalado con la opción *"Install Npcap in WinPcap API-compatible Mode"* habilitada.

---

## 🚀 Instalación y Puesta en Marcha

1. **Clonar el repositorio:**
   ```powershell
   git clone https://github.com/<TU_USUARIO>/nids-ia-proyecto.git
   cd nids-ia-proyecto
   ```

2. **Crear y activar el entorno virtual:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. **Instalar las dependencias:**
   ```powershell
   pip install -r requirements.txt
   ```

4. **Ejecutar el Dashboard NIDS (en PowerShell como Administrador):**
   ```powershell
   cd src
   python -m streamlit run dashboard.py
   ```
   *(Nota: Se invoca mediante `python -m` para evitar bloqueos de ejecución de binarios `.exe` en políticas restrictivas de Windows).*

5. **Operación en el navegador:**
   * Abre `http://localhost:8501`.
   * Presiona **▶️ Iniciar** en el panel lateral izquierdo para comenzar la captura en vivo en ventanas configurables (por defecto 3 segundos).
   * Utiliza **🧪 Simular traza de ataque (Replay)** para validar la respuesta del modelo ante muestras reales no vistas del conjunto de prueba (`30%` split).
   * Exporta las detecciones en formato tabular mediante **📥 Exportar logs (.CSV)**.

---

## 📊 Rendimiento del Modelo

* **Algoritmo:** Random Forest Classifier (`scikit-learn`).
* **Dataset:** CIC-IDS2017 (`DDoS-Friday-no-metadata.parquet`), dividido de forma estratificada en 70% entrenamiento y 30% validación.
* **Vector de entrada:** 77 características estadísticas de flujo bidireccional (tasas de bytes/paquetes por segundo, estadísticas de Inter-Arrival Time en microsegundos, conteo de banderas TCP, tamaños de ventana y longitudes de segmento).
* **Métricas en validación:** Precisión, Recall y F1-Score de `1.00` sobre el conjunto de prueba.

---

## ⚠️ Aviso de Uso Académico

Este software y su módulo auxiliar (`src/simulador_ataque.py`) han sido desarrollados exclusivamente con fines educativos, de investigación y validación en entornos de red locales controlados.