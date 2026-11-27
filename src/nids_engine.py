
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP

RUTA_MODELO = "../models/nids_random_forest.joblib"

def stats_lista(valores):
    """Devuelve (max, min, mean, std) de una lista numérica."""
    if not valores:
        return 0.0, 0.0, 0.0, 0.0
    arr = np.array(valores, dtype=np.float64)
    std = float(np.std(arr, ddof=1)) if len(arr) > 1 else 0.0
    return float(np.max(arr)), float(np.min(arr)), float(np.mean(arr)), std

def stats_iat(timestamps):
    """Calcula estadísticas de Inter-Arrival Time (en microsegundos)."""
    if len(timestamps) < 2:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    diffs = np.diff(timestamps) * 1_000_000.0
    std = float(np.std(diffs, ddof=1)) if len(diffs) > 1 else 0.0
    return (
        float(np.sum(diffs)),
        float(np.mean(diffs)),
        std,
        float(np.max(diffs)),
        float(np.min(diffs)),
    )

class NIDSEngine:
    def __init__(self, ruta_modelo=RUTA_MODELO):
        self.modelo = joblib.load(ruta_modelo)
        self.columnas_modelo = list(self.modelo.feature_names_in_)
        self.flujos_activos = {}

    def _clave_flujo(self, ip_src, sport, ip_dst, dport, proto):
        ep_a = (ip_src, sport)
        ep_b = (ip_dst, dport)
        return (ep_a, ep_b, proto) if ep_a < ep_b else (ep_b, ep_a, proto)

    def procesar_paquete(self, paquete):
        if IP not in paquete:
            return

        ip_src = paquete[IP].src
        ip_dst = paquete[IP].dst
        ts = float(paquete.time)

        if TCP in paquete:
            proto = 6
            sport = int(paquete[TCP].sport)
            dport = int(paquete[TCP].dport)
            payload_len = len(paquete[TCP].payload)
            header_len = int(paquete[TCP].dataofs) * 4 if paquete[TCP].dataofs else 20
            win_size = int(paquete[TCP].window)
            flags = str(paquete[TCP].flags)
        elif UDP in paquete:
            proto = 17
            sport = int(paquete[UDP].sport)
            dport = int(paquete[UDP].dport)
            payload_len = len(paquete[UDP].payload)
            header_len = 8
            win_size = -1
            flags = ""
        else:
            return

        clave = self._clave_flujo(ip_src, sport, ip_dst, dport, proto)

        if clave not in self.flujos_activos:
            self.flujos_activos[clave] = {
                "src_ip": ip_src,
                "src_port": sport,
                "dst_ip": ip_dst,
                "dst_port": dport,
                "proto": proto,
                "all_ts": [],
                "fwd_ts": [],
                "bwd_ts": [],
                "fwd_lens": [],
                "bwd_lens": [],
                "fwd_hdrs": [],
                "bwd_hdrs": [],
                "init_fwd_win": win_size,
                "init_bwd_win": -1,
                "fwd_psh": 0, "bwd_psh": 0,
                "fwd_urg": 0, "bwd_urg": 0,
                "fin": 0, "syn": 0, "rst": 0, "psh": 0,
                "ack": 0, "urg": 0, "cwe": 0, "ece": 0,
            }

        f = self.flujos_activos[clave]
        f["all_ts"].append(ts)

        es_fwd = (ip_src == f["src_ip"] and sport == f["src_port"])
        if es_fwd:
            f["fwd_ts"].append(ts)
            f["fwd_lens"].append(payload_len)
            f["fwd_hdrs"].append(header_len)
        else:
            if f["init_bwd_win"] == -1 and proto == 6:
                f["init_bwd_win"] = win_size
            f["bwd_ts"].append(ts)
            f["bwd_lens"].append(payload_len)
            f["bwd_hdrs"].append(header_len)

        if proto == 6:
            if "F" in flags: f["fin"] += 1
            if "S" in flags: f["syn"] += 1
            if "R" in flags: f["rst"] += 1
            if "P" in flags:
                f["psh"] += 1
                if es_fwd: f["fwd_psh"] += 1
                else: f["bwd_psh"] += 1
            if "A" in flags: f["ack"] += 1
            if "U" in flags:
                f["urg"] += 1
                if es_fwd: f["fwd_urg"] += 1
                else: f["bwd_urg"] += 1
            if "C" in flags: f["cwe"] += 1
            if "E" in flags: f["ece"] += 1

    def _extraer_vector(self, f):
        dur_us = (f["all_ts"][-1] - f["all_ts"][0]) * 1_000_000.0 if len(f["all_ts"]) > 1 else 0.0
        dur_s = dur_us / 1_000_000.0

        tot_fwd = len(f["fwd_lens"])
        tot_bwd = len(f["bwd_lens"])
        tot_pkts = tot_fwd + tot_bwd

        sum_fwd = float(sum(f["fwd_lens"]))
        sum_bwd = float(sum(f["bwd_lens"]))
        all_lens = f["fwd_lens"] + f["bwd_lens"]

        fwd_max, fwd_min, fwd_mean, fwd_std = stats_lista(f["fwd_lens"])
        bwd_max, bwd_min, bwd_mean, bwd_std = stats_lista(f["bwd_lens"])
        pkt_max, pkt_min, pkt_mean, pkt_std = stats_lista(all_lens)
        pkt_var = pkt_std ** 2

        _, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = stats_iat(f["all_ts"])
        fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = stats_iat(f["fwd_ts"])
        bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = stats_iat(f["bwd_ts"])

        flow_bytes_s = ((sum_fwd + sum_bwd) / dur_s) if dur_s > 0 else 0.0
        flow_pkts_s = (tot_pkts / dur_s) if dur_s > 0 else 0.0
        fwd_pkts_s = (tot_fwd / dur_s) if dur_s > 0 else 0.0
        bwd_pkts_s = (tot_bwd / dur_s) if dur_s > 0 else 0.0

        down_up = float(tot_bwd / tot_fwd) if tot_fwd > 0 else 0.0
        avg_pkt = (sum(all_lens) / tot_pkts) if tot_pkts > 0 else 0.0
        fwd_act_data = sum(1 for x in f["fwd_lens"] if x > 0)
        fwd_seg_min = min(f["fwd_hdrs"]) if f["fwd_hdrs"] else 0

        return {
            "Protocol": f["proto"],
            "Flow Duration": dur_us,
            "Total Fwd Packets": tot_fwd,
            "Total Backward Packets": tot_bwd,
            "Fwd Packets Length Total": sum_fwd,
            "Bwd Packets Length Total": sum_bwd,
            "Fwd Packet Length Max": fwd_max,
            "Fwd Packet Length Min": fwd_min,
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": fwd_std,
            "Bwd Packet Length Max": bwd_max,
            "Bwd Packet Length Min": bwd_min,
            "Bwd Packet Length Mean": bwd_mean,
            "Bwd Packet Length Std": bwd_std,
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_pkts_s,
            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Std": flow_iat_std,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,
            "Fwd IAT Total": fwd_iat_tot,
            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_std,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,
            "Bwd IAT Total": bwd_iat_tot,
            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_std,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,
            "Fwd PSH Flags": f["fwd_psh"],
            "Bwd PSH Flags": f["bwd_psh"],
            "Fwd URG Flags": f["fwd_urg"],
            "Bwd URG Flags": f["bwd_urg"],
            "Fwd Header Length": sum(f["fwd_hdrs"]),
            "Bwd Header Length": sum(f["bwd_hdrs"]),
            "Fwd Packets/s": fwd_pkts_s,
            "Bwd Packets/s": bwd_pkts_s,
            "Packet Length Min": pkt_min,
            "Packet Length Max": pkt_max,
            "Packet Length Mean": pkt_mean,
            "Packet Length Std": pkt_std,
            "Packet Length Variance": pkt_var,
            "FIN Flag Count": f["fin"],
            "SYN Flag Count": f["syn"],
            "RST Flag Count": f["rst"],
            "PSH Flag Count": f["psh"],
            "ACK Flag Count": f["ack"],
            "URG Flag Count": f["urg"],
            "CWE Flag Count": f["cwe"],
            "ECE Flag Count": f["ece"],
            "Down/Up Ratio": down_up,
            "Avg Packet Size": avg_pkt,
            "Avg Fwd Segment Size": fwd_mean,
            "Avg Bwd Segment Size": bwd_mean,
            "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0,
            "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0,
            "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0,
            "Subflow Fwd Packets": tot_fwd,
            "Subflow Fwd Bytes": sum_fwd,
            "Subflow Bwd Packets": tot_bwd,
            "Subflow Bwd Bytes": sum_bwd,
            "Init Fwd Win Bytes": f["init_fwd_win"],
            "Init Bwd Win Bytes": f["init_bwd_win"],
            "Fwd Act Data Packets": fwd_act_data,
            "Fwd Seg Size Min": fwd_seg_min,
            "Active Mean": 0.0, "Active Std": 0.0, "Active Max": 0.0, "Active Min": 0.0,
            "Idle Mean": 0.0, "Idle Std": 0.0, "Idle Max": 0.0, "Idle Min": 0.0,
        }

    def analizar_ventana(self, duracion_ventana=3):
        """Captura tráfico durante `duracion_ventana` segundos y clasifica cada flujo."""
        self.flujos_activos.clear()
        sniff(filter="ip", prn=self.procesar_paquete, store=False, timeout=duracion_ventana)

        if not self.flujos_activos:
            return []

        metadatos = []
        vectores = []
        for f in self.flujos_activos.values():
            metadatos.append(f)
            vectores.append(self._extraer_vector(f))

        df_features = pd.DataFrame(vectores)[self.columnas_modelo]
        predicciones = self.modelo.predict(df_features)
        probabilidades = self.modelo.predict_proba(df_features)

        resultados = []
        hora = datetime.now().strftime("%H:%M:%S")
        for meta, pred, probs in zip(metadatos, predicciones, probabilidades):
            resultados.append({
                "hora": hora,
                "origen": f"{meta['src_ip']}:{meta['src_port']}",
                "destino": f"{meta['dst_ip']}:{meta['dst_port']}",
                "protocolo": "TCP" if meta["proto"] == 6 else "UDP",
                "paquetes": len(meta["fwd_lens"]) + len(meta["bwd_lens"]),
                "etiqueta": "ATAQUE DDoS" if pred == 1 else "Normal",
                "es_ataque": bool(pred == 1),
                "confianza": round(float(probs[pred]) * 100, 1)
            })
        return resultados

if __name__ == "__main__":
    print("Cargando modelo Random Forest y arrancando NIDS en tiempo real...")
    print("Presiona Ctrl + C para detener (tarda máx. 3s en cerrar).\n")
    motor = NIDSEngine()
    try:
        while True:
            eventos = motor.analizar_ventana(duracion_ventana=3)
            ataques = [e for e in eventos if e["es_ataque"]]
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Flujos analizados: {len(eventos)} | Amenazas detectadas: {len(ataques)}")
            for a in ataques:
                print(f"   >>> [ALERTA {a['confianza']}%] {a['protocolo']} {a['origen']} -> {a['destino']} ({a['paquetes']} pkts)")
    except KeyboardInterrupt:
        print("\nMotor NIDS detenido.")