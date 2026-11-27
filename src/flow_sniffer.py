import time
import numpy as np
from scapy.all import sniff, IP, TCP, UDP

# Diccionario temporal para almacenar los flujos activos en cada ventana
flujos_activos = {}

def obtener_clave_flujo(ip_src, sport, ip_dst, dport, proto):
    """Normaliza la 5-tupla para agrupar tráfico de ida y vuelta en el mismo flujo."""
    endpoint_a = (ip_src, sport)
    endpoint_b = (ip_dst, dport)
    if endpoint_a < endpoint_b:
        return (endpoint_a, endpoint_b, proto)
    return (endpoint_b, endpoint_a, proto)

def procesar_paquete(paquete):
    if IP not in paquete:
        return

    ip_src = paquete[IP].src
    ip_dst = paquete[IP].dst
    tamaño = len(paquete)
    timestamp = float(paquete.time)

    sport, dport, proto = 0, 0, 0
    flags_str = ""

    if TCP in paquete:
        proto = 6
        sport = paquete[TCP].sport
        dport = paquete[TCP].dport
        flags_str = str(paquete[TCP].flags)
    elif UDP in paquete:
        proto = 17
        sport = paquete[UDP].sport
        dport = paquete[UDP].dport
    else:
        return  # Ignoramos protocolos sin puertos (ej. ICMP) para mantener compatibilidad con CIC-IDS

    clave = obtener_clave_flujo(ip_src, sport, ip_dst, dport, proto)

    # Si es el primer paquete del flujo, lo inicializamos y definimos la dirección Forward
    if clave not in flujos_activos:
        flujos_activos[clave] = {
            "fwd_ip": ip_src,
            "fwd_port": sport,
            "dst_ip": ip_dst,
            "dst_port": dport,
            "proto": proto,
            "start_time": timestamp,
            "last_time": timestamp,
            "fwd_lengths": [],
            "bwd_lengths": [],
            "syn_count": 0,
            "ack_count": 0,
            "fin_count": 0,
            "rst_count": 0,
            "psh_count": 0
        }

    flujo = flujos_activos[clave]
    flujo["last_time"] = timestamp

    # Clasificar dirección del paquete (Forward vs Backward)
    if ip_src == flujo["fwd_ip"] and sport == flujo["fwd_port"]:
        flujo["fwd_lengths"].append(tamaño)
    else:
        flujo["bwd_lengths"].append(tamaño)

    # Contar banderas TCP (clave para detectar DDoS y escaneos)
    if proto == 6:
        if "S" in flags_str: flujo["syn_count"] += 1
        if "A" in flags_str: flujo["ack_count"] += 1
        if "F" in flags_str: flujo["fin_count"] += 1
        if "R" in flags_str: flujo["rst_count"] += 1
        if "P" in flags_str: flujo["psh_count"] += 1

def resumir_flujos(flujos):
    print(f"\n--- {len(flujos)} Flujos Reconstruidos en esta ventana ---")
    for clave, f in list(flujos.items())[:10]:  # Mostramos máximo 10 por pantalla
        duracion_us = (f["last_time"] - f["start_time"]) * 1_000_000  # Microsegundos (formato CIC-IDS)
        total_fwd = len(f["fwd_lengths"])
        total_bwd = len(f["bwd_lengths"])
        bytes_totales = sum(f["fwd_lengths"]) + sum(f["bwd_lengths"])
        proto_nombre = "TCP" if f["proto"] == 6 else "UDP"

        print(
            f"[{proto_nombre}] {f['fwd_ip']}:{f['fwd_port']} <-> {f['dst_ip']}:{f['dst_port']} | "
            f"Duración: {duracion_us:.0f} µs | Pkts (Fwd/Bwd): {total_fwd}/{total_bwd} | "
            f"Bytes: {bytes_totales} | SYN:{f['syn_count']} ACK:{f['ack_count']}"
        )

if __name__ == "__main__":
    print("Iniciando Reconstructor de Flujos NIDS (Ventanas de 5 segundos)...")
    print("Presiona Ctrl + C para detener.\n")
    try:
        while True:
            flujos_activos.clear()
            sniff(filter="ip", prn=procesar_paquete, store=False, timeout=5)
            resumir_flujos(flujos_activos)
    except KeyboardInterrupt:
        print("\nCaptura detenida por el usuario.")