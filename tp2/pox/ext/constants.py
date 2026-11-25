from pox.lib.addresses import EthAddr, IPAddr  # Address types

PRIVATE_IP = IPAddr("192.168.1.254")  # IP del router en la red privada
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")  # MAC del router hacia la red privada
PRIVATE_MASK = 24  # Máscara de la red interna
PRIVATE_SUBNET = IPAddr("192.168.1.0")  # Red interna

PUBLIC_IP = IPAddr("200.0.0.254")  # IP del router en la red pública
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")  # MAC del router hacia la red pública
PUBLIC_PORT = 1  # Puerto del switch conectado a la red pública
# Rango de puertos públicos que asigna el NAT
PUERTO_PUBLICO_MIN = 10000
PUERTO_PUBLICO_MAX = 65535

# Tiempo de vida de una entrada de la tabla ARP.
ARP_TTL = 60
# Segundos que se retiene un paquete esperando un ARP Reply antes de descartarlo
ARP_ESPERA_MAX = 5

TIMEOUT = 20

MAC_CERO = EthAddr("00:00:00:00:00:00")
MAC_BROADCAST = EthAddr("ff:ff:ff:ff:ff:ff")
