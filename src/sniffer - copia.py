from scapy.all import sniff, IP, TCP, UDP

def procesar_paquete(paquete):
    # Verificamos que el paquete tenga la capa IP (Internet Protocol)
    if IP in paquete:
        ip_src = paquete[IP].src
        ip_dst = paquete[IP].dst
        tamaño = len(paquete)
        
        # Identificamos el protocolo (TCP o UDP)
        proto = "Otro"
        if TCP in paquete:
            proto = "TCP"
        elif UDP in paquete:
            proto = "UDP"
            
        print(f"[{proto}] {ip_src} -> {ip_dst} | Tamaño: {tamaño} bytes")

print("Iniciando Motor de Captura NIDS...")
print("Escuchando tráfico de red (Mostrando los primeros 10 paquetes)...")

# sniff captura el tráfico. 
# store=False evita que la memoria RAM se llene.
# count=10 detiene el script después de 10 paquetes para esta primera prueba.
sniff(filter="ip", prn=procesar_paquete, store=False, count=10)

print("Prueba de captura finalizada.")