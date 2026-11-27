import os
import time
from datetime import datetime
import numpy as np
import pandas as pd
import streamlit as st
from sklearn.model_selection import train_test_split
from nids_engine import NIDSEngine

# Configuración de la página
st.set_page_config(
    page_title="NIDS-IA | Monitor de Intrusiones",
    page_icon="🛡️",
    layout="wide"
)

# Rutas seguras hacia el modelo y dataset de validación
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RUTA_MODELO = os.path.join(BASE_DIR, "..", "models", "nids_random_forest.joblib")
RUTA_DATASET = os.path.join(BASE_DIR, "..", "data", "DDoS-Friday-no-metadata.parquet")

@st.cache_resource
def cargar_motor():
    return NIDSEngine(ruta_modelo=RUTA_MODELO)

@st.cache_data
def cargar_muestras_prueba():
    """Carga flujos reales no vistos (split de prueba 30%) para validación segura."""
    df = pd.read_parquet(RUTA_DATASET)
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    col_label = "Label" if "Label" in df.columns else "label"
    _, X_test = train_test_split(df, test_size=0.3, random_state=42, stratify=df[col_label])
    return X_test

# Inicializar estado de la sesión
if "monitoreo" not in st.session_state:
    st.session_state.monitoreo = False
if "eventos" not in st.session_state:
    st.session_state.eventos = []
if "historial_ventanas" not in st.session_state:
    st.session_state.historial_ventanas = []

motor = cargar_motor()

# --- BARRA LATERAL (CONTROLES) ---
with st.sidebar:
    st.title("🛡️ Control NIDS-IA")
    st.markdown("Sistema de Detección de Intrusiones impulsado por **Random Forest**.")
    st.divider()

    col_btn1, col_btn2 = st.columns(2)
    if col_btn1.button("▶️ Iniciar", use_container_width=True, disabled=st.session_state.monitoreo):
        st.session_state.monitoreo = True
        st.rerun()

    if col_btn2.button("⏹️ Detener", use_container_width=True, disabled=not st.session_state.monitoreo):
        st.session_state.monitoreo = False
        st.rerun()

    estado_texto = "🟢 Monitoreando red en vivo" if st.session_state.monitoreo else "⚪ En pausa"
    st.info(estado_texto)

    duracion = st.slider("Ventana de captura (segundos)", min_value=2, max_value=10, value=3)

    st.divider()
    if st.button("🧪 Simular traza de ataque (Replay)", use_container_width=True):
        X_test_pool = cargar_muestras_prueba()
        muestra = X_test_pool.sample(n=15)
        features = muestra[motor.columnas_modelo]

        preds = motor.modelo.predict(features)
        probs = motor.modelo.predict_proba(features)
        hora_actual = datetime.now().strftime("%H:%M:%S")

        nuevos = []
        for i, (pred, prob) in enumerate(zip(preds, probs)):
            proto_num = int(muestra.iloc[i]["Protocol"])
            pkts = int(muestra.iloc[i]["Total Fwd Packets"] + muestra.iloc[i]["Total Backward Packets"])
            nuevos.append({
                "hora": hora_actual,
                "origen": f"172.16.0.{10 + i}:{49152 + i}",
                "destino": "192.168.10.50:80",
                "protocolo": "TCP" if proto_num == 6 else "UDP",
                "paquetes": pkts,
                "etiqueta": "ATAQUE DDoS" if pred == 1 else "Normal",
                "es_ataque": bool(pred == 1),
                "confianza": round(float(prob[pred]) * 100, 1)
            })

        ataques_rep = sum(1 for e in nuevos if e["es_ataque"])
        normales_rep = len(nuevos) - ataques_rep

        st.session_state.eventos.extend(nuevos)
        if len(st.session_state.eventos) > 1000:
            st.session_state.eventos = st.session_state.eventos[-1000:]

        st.session_state.historial_ventanas.append({
            "Hora": hora_actual,
            "Normal": normales_rep,
            "Ataque": ataques_rep
        })
        if len(st.session_state.historial_ventanas) > 25:
            st.session_state.historial_ventanas = st.session_state.historial_ventanas[-25:]

        st.rerun()

    if st.button("🗑️ Limpiar registros", use_container_width=True):
        st.session_state.eventos = []
        st.session_state.historial_ventanas = []
        st.rerun()

    if st.session_state.eventos:
        df_export = pd.DataFrame(st.session_state.eventos)
        csv = df_export.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="📥 Exportar logs (.CSV)",
            data=csv,
            file_name=f"nids_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )

# --- PANEL PRINCIPAL ---
st.title("Monitor de Tráfico y Detección de Intrusiones (NIDS)")

df_eventos = pd.DataFrame(st.session_state.eventos)
total_flujos = len(df_eventos)
total_ataques = int(df_eventos["es_ataque"].sum()) if total_flujos > 0 else 0
total_normal = total_flujos - total_ataques
tasa_ataque = (total_ataques / total_flujos * 100) if total_flujos > 0 else 0.0

# Tarjetas de métricas (KPIs)
kpi1, kpi2, kpi3, kpi4 = st.columns(4)
kpi1.metric("Flujos Analizados", f"{total_flujos:,}")
kpi2.metric("Tráfico Normal", f"{total_normal:,}")
kpi3.metric("Amenazas Detectadas (DDoS)", f"{total_ataques:,}")
kpi4.metric("Tasa de Anomalías", f"{tasa_ataque:.1f}%")

st.divider()

# Sección de Alertas y Gráfica
col_izq, col_der = st.columns([1.2, 1])

with col_izq:
    st.subheader("🚨 Panel de Alertas")
    if total_ataques > 0:
        df_ataques = df_eventos[df_eventos["es_ataque"] == True][
            ["hora", "protocolo", "origen", "destino", "paquetes", "confianza"]
        ].iloc[::-1]
        ultimo = df_ataques.iloc[0]
        st.error(
            f"**Última amenaza:** {ultimo['protocolo']} desde `{ultimo['origen']}` hacia `{ultimo['destino']}` "
            f"(Confianza: {ultimo['confianza']}%)"
        )
        st.dataframe(df_ataques, use_container_width=True, height=250, hide_index=True)
    else:
        st.success("Sin amenazas detectadas en los registros actuales.")

with col_der:
    st.subheader("📊 Actividad por Ventana de Tiempo")
    if st.session_state.historial_ventanas:
        df_hist = pd.DataFrame(st.session_state.historial_ventanas).set_index("Hora")
        st.bar_chart(df_hist[["Normal", "Ataque"]], color=["#2ecc71", "#e74c3c"], height=310)
    else:
        st.caption("Presiona **Iniciar** en el menú lateral para comenzar a graficar el tráfico.")

# Tabla completa de eventos recientes
st.subheader("📋 Registro de Flujos de Red (Últimos 100)")
if total_flujos > 0:
    df_tabla = df_eventos[
        ["hora", "etiqueta", "confianza", "protocolo", "origen", "destino", "paquetes"]
    ].iloc[::-1].head(100)
    st.dataframe(df_tabla, use_container_width=True, height=280, hide_index=True)
else:
    st.caption("Aún no hay flujos registrados.")

# --- BUCLE DE CAPTURA EN VIVO ---
if st.session_state.monitoreo:
    with st.spinner(f"Analizando paquetes de red ({duracion}s)..."):
        nuevos_eventos = motor.analizar_ventana(duracion_ventana=duracion)

    ataques_ventana = sum(1 for e in nuevos_eventos if e["es_ataque"])
    normales_ventana = len(nuevos_eventos) - ataques_ventana

    st.session_state.eventos.extend(nuevos_eventos)
    if len(st.session_state.eventos) > 1000:
        st.session_state.eventos = st.session_state.eventos[-1000:]

    st.session_state.historial_ventanas.append({
        "Hora": datetime.now().strftime("%H:%M:%S"),
        "Normal": normales_ventana,
        "Ataque": ataques_ventana
    })
    if len(st.session_state.historial_ventanas) > 25:
        st.session_state.historial_ventanas = st.session_state.historial_ventanas[-25:]

    time.sleep(0.1)
    st.rerun()