import random
import sys
import time
from scapy.all import Ether, IP, TCP, Raw, sendp, getmacbyip, conf

conf.verb = 0

def obtener_red_local():
    """Obtiene la interfaz activa y la IP del router/gateway por defecto."""
    iface, _, gateway = conf.route.route("0.0.0.0")
    return iface, gateway

def simular_rafaga_ddos(ip_destino, puerto_destino=80, num_flujos=15, pkts_por_flujo=25):
    iface, _ = obtener_red_local()
    mac_destino = getmacbyip(ip_destino) or "ff:ff:ff:ff:ff:ff"
    total_paquetes = num_flujos * pkts_por_flujo

    print("Iniciando simulación controlada de tráfico tipo DDoS (HTTP Flood)...")
    print(f"Interfaz: {iface} | Objetivo: {ip_destino}:{puerto_destino} | Flujos: {num_flujos} ({total_paquetes} pkts)")

    # Cargas HTTP variables con banderas PSH+ACK y ventana 8192 (patrón DDoS de CIC-IDS2017)
    payloads = [
        b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: LOIC\r\n\r\n",
        b"GET /index.html?id=" + (b"A" * 120) + b" HTTP/1.1\r\nHost: target\r\n\r\n",
        b"POST /login HTTP/1.1\r\nHost: target\r\nContent-Length: 180\r\n\r\n" + (b"X" * 180),
    ]

    rafaga = []
    for i in range(num_flujos):
        sport = 44440 + i
        rafaga.append(
            Ether(dst=mac_destino)
            / IP(dst=ip_destino)
            / TCP(sport=sport, dport=puerto_destino, flags="S", window=8192)
        )
        for _ in range(pkts_por_flujo - 1):
            carga = random.choice(payloads)
            rafaga.append(
                Ether(dst=mac_destino)
                / IP(dst=ip_destino)
                / TCP(sport=sport, dport=puerto_destino, flags="PA", window=8192)
                / Raw(load=carga)
            )

    inicio = time.time()
    sendp(rafaga, iface=iface, inter=0.002, verbose=False)
    duracion = time.time() - inicio

    print(f"Simulación finalizada en {duracion:.2f}s ({total_paquetes / duracion:.0f} pkts/s).")
    print("Espera 3 segundos y verifica el Panel de Alertas en el Dashboard.")

if __name__ == "__main__":
    _, gateway_default = obtener_red_local()
    destino = sys.argv[1] if len(sys.argv) > 1 else gateway_default
    simular_rafaga_ddos(ip_destino=destino)