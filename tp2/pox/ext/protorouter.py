# Import some POX stuff
from pox.core import core  # Main POX object
import pox.openflow.libopenflow_01 as of  # OpenFlow 1.0 library
from pox.lib.addresses import EthAddr, IPAddr  # Address types
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp  # capa de enlace/red
from pox.lib.packet.ipv4 import ipv4  # capa de red
from pox.lib.packet.tcp import tcp  # capa de transporte
from pox.lib.packet.udp import udp  # capa de transporte
from constants import *
import time

log = core.getLogger()
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def log_color(color, msg):
    log.info(f"{color}{msg}{RESET}")


class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        # Tabla para tráfico saliente (De Privado a Público)
        # Llave: (Protocolo, IP_Privada, Puerto_Privado) -> Valor: Puerto_Publico_Asignado
        self.nat_saliente = {}

        # Tabla para tráfico entrante (De Público a Privado)
        # Llave: (Protocolo, Puerto_Publico_Asignado) -> Valor: (IP_Privada, Puerto_Privado)
        self.nat_entrante = {}

        # Variable para asignar puertos públicos dinámicamente (empezamos en un puerto alto para evitar colisiones)
        self.siguiente_puerto_publico = PUERTO_PUBLICO_MIN

        # Puertos publicos que se usaron y ya se liberaron
        self.puertos_libres = set()

        # Reglas que se encuentran instaladas en cada puerto del switch
        # (Protocolo , Puerto Publico) -> Conjunto de reglas
        self.reglas_por_puerto = {}

        # Tabla ARP:
        # Clave: IP -> Valor: MAC
        self.tabla_arp = {}

        # Clave: IP -> Valor: instante en que se aprendió/refresco la entrada
        self.arp_visto = {}

        # Puerto del switch donde está cada host privado
        # Clave: IP privada -> Valor: número de puerto
        self.puerto_por_ip = {}

        # Clave: IP -> Valor: Lista de paquetes trabados esperando esa IP
        self.paquetes_en_espera = {}

    def _handle_PacketIn(self, event):
        try:
            parseado = event.parsed.parsed
        except Exception:
            # POX puede fallar al decodificar algunos paquetes (ej. ICMP unreachable)
            parseado = False
        if not parseado:
            log.warning(
                "[DROP] PacketIn con trama no reconocida. POX no pudo decodificar el paquete."
            )
            return

        if event.parsed.type == ethernet.IP_TYPE:
            self.handle_ip(event)
        elif event.parsed.type == ethernet.ARP_TYPE:
            self.handle_arp(event)
        else:
            log_color(YELLOW, f"Paquete ignorado: protocolo distinto de IPv4.")

    def _handle_FlowRemoved(self, event):
        # El switch borro una regla (por timeout) y nos avisa gracias al flag OFPFF_SEND_FLOW_REM
        match = event.ofp.match  # el "si el paquete..." de la regla que se borro
        log_color(
            CYAN,
            f"REGLA BORRADA: {match.nw_src}:{match.tp_src} → {match.nw_dst}:{match.tp_dst} | "
            f"In Port: {match.in_port} | Por timeout: {event.idleTimeout}",
        )

        # A que puerto público pertenecía esta regla?
        if match.in_port == PUBLIC_PORT:
            # Regla entrante: el puerto publico es el puerto destino
            puerto_publico = match.tp_dst
        else:
            # Regla saliente: lo buscamos en la tabla con (protocolo, IP privada, puerto privado)
            puerto_publico = self.nat_saliente.get(
                (match.nw_proto, match.nw_src, match.tp_src)
            )

        clave_puerto = (match.nw_proto, puerto_publico)
        if clave_puerto not in self.reglas_por_puerto:
            return  # no es una regla nuestra, o el puerto ya se liberó

        # Tachamos la regla borrada
        reglas = self.reglas_por_puerto[clave_puerto]
        reglas.discard(self.clave_regla(match))

        # Si no queda ninguna regla usando este puerto, la conexión terminó: liberamos
        if not reglas:
            del self.reglas_por_puerto[clave_puerto]
            ip_privada, puerto_privado = self.nat_entrante.pop(clave_puerto)
            del self.nat_saliente[(match.nw_proto, ip_privada, puerto_privado)]
            log_color(
                GREEN,
                f"PUERTO LIBERADO: {PUBLIC_IP}:{puerto_publico} (era de {ip_privada}:{puerto_privado})",
            )
            self.puertos_libres.add(puerto_publico)

    def handle_arp(self, event):
        paquete = event.parsed
        puerto_entrada = event.port
        datagrama_arp: arp = paquete.payload
        ip_src = datagrama_arp.protosrc
        mac_src = datagrama_arp.hwsrc

        self.aprender_arp(ip_src, mac_src)
        log_color(GREEN, f"ARP aprendido {ip_src} -> {mac_src}")

        if datagrama_arp.opcode == arp.REQUEST:
            ip_buscada = datagrama_arp.protodst
            mac_respuesta = None

            if ip_buscada == PRIVATE_IP:
                mac_respuesta = PRIVATE_MAC
            elif ip_buscada == PUBLIC_IP:
                mac_respuesta = PUBLIC_MAC

            if mac_respuesta:
                arp_reply = arp()
                arp_reply.opcode = arp.REPLY
                arp_reply.hwsrc = mac_respuesta
                arp_reply.hwdst = mac_src
                arp_reply.protosrc = ip_buscada
                arp_reply.protodst = ip_src

                eth_reply = ethernet()
                eth_reply.type = ethernet.ARP_TYPE
                eth_reply.src = mac_respuesta
                eth_reply.dst = mac_src
                eth_reply.payload = arp_reply

                msg = of.ofp_packet_out()
                msg.data = eth_reply.pack()
                msg.actions.append(of.ofp_action_output(port=puerto_entrada))

                self.connection.send(msg)

                log_color(GREEN, f"arp reply enviado: {ip_buscada} es {mac_respuesta}")
            else:
                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.in_port = puerto_entrada
                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                self.connection.send(msg)

        elif datagrama_arp.opcode == arp.REPLY:
            log_color(GREEN, f"ARP Reply recibido: la MAC de {ip_src} es {mac_src}")

            for datos in self.paquetes_en_espera.pop(ip_src, []):
                log_color(YELLOW, f"Desbloqueando paquete hacia {ip_src}")
                # Recién ahora que conocemos la MAC le asignamos puerto público
                puerto_publico = self.obtener_puerto_publico(
                    datos["ipv4"], datos["transporte"]
                )
                if (
                    puerto_publico is None
                    and datos["ipv4"].protocol != ipv4.ICMP_PROTOCOL
                ):
                    log_color(
                        RED,
                        f"SIN PUERTOS: no quedan puertos públicos libres, se descarta {datos['ipv4'].srcip}",
                    )
                    continue
                self.instalar_flujos(
                    datos["packet"],
                    datos["in_port"],
                    datos["ipv4"],
                    datos["transporte"],
                    puerto_publico,
                )

    def handle_ip(self, event):
        # desarmamos el paquete (tipo mamushka)
        paquete = event.parsed
        puerto_entrada = event.port
        datagrama_ip = paquete.payload
        segmento_transp = datagrama_ip.payload

        log_color(
            YELLOW,
            f"RECIBIDO: {datagrama_ip.srcip} → {datagrama_ip.dstip} | "
            f"MAC: {paquete.src} → {paquete.dst} | In Port: {puerto_entrada}",
        )

        self.aprender_arp(datagrama_ip.srcip, paquete.src)
        self.limpiar_espera()

        if datagrama_ip.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            self.puerto_por_ip[datagrama_ip.srcip] = puerto_entrada

            log_color(
                GREEN,
                f"MATCH: {datagrama_ip.srcip} pertenece a la red privada {PRIVATE_SUBNET}/{PRIVATE_MASK}",
            )

            # Verificar que sea TCP, UDP o ICMP
            if datagrama_ip.protocol not in (
                ipv4.TCP_PROTOCOL,
                ipv4.UDP_PROTOCOL,
                ipv4.ICMP_PROTOCOL,
            ):
                log_color(
                    YELLOW,
                    f"Paquete ignorado: protocolo de transporte {datagrama_ip.protocol} no soportado.",
                )
                return

            # Si no conozco la MAC del destino, guardo el paquete y pregunto por ARP.
            # Todavía no le asigno puerto público: si el ARP nunca se responde,
            # el puerto quedaría reservado sin reglas y nunca se liberaría.
            ip_destino = datagrama_ip.dstip
            if self.mac_de(ip_destino) is None:
                datos_paquete = {
                    "packet": paquete,
                    "in_port": puerto_entrada,
                    "ipv4": datagrama_ip,
                    "transporte": segmento_transp,
                    "tiempo": time.time(),
                }
                ya_esperando = ip_destino in self.paquetes_en_espera
                self.paquetes_en_espera.setdefault(ip_destino, []).append(datos_paquete)
                if not ya_esperando:
                    log_color(
                        YELLOW, f"MAC de {ip_destino} desconocida, envio ARP Request"
                    )
                    self.enviar_arp_request(ip_destino)
                return

            puerto_publico = self.obtener_puerto_publico(datagrama_ip, segmento_transp)
            if puerto_publico is None and datagrama_ip.protocol != ipv4.ICMP_PROTOCOL:
                log_color(
                    RED,
                    f"SIN PUERTOS: no quedan puertos públicos libres, se descarta {datagrama_ip.srcip}",
                )
                return
            self.instalar_flujos(
                paquete, puerto_entrada, datagrama_ip, segmento_transp, puerto_publico
            )

        else:
            if (
                puerto_entrada == PUBLIC_PORT
                and datagrama_ip.dstip == PUBLIC_IP
                and datagrama_ip.protocol in (ipv4.TCP_PROTOCOL, ipv4.UDP_PROTOCOL)
                and (datagrama_ip.protocol, segmento_transp.dstport)
                in self.nat_entrante
            ):
                self.reinstalar_flujo_entrante(paquete, datagrama_ip, segmento_transp)
                return

            log_color(
                RED,
                f"NO MATCH: {datagrama_ip.srcip} no pertenece a {PRIVATE_SUBNET}/{PRIVATE_MASK}",
            )

    def reinstalar_flujo_entrante(self, paquete, datagrama_ip, segmento_transp):
        protocolo = datagrama_ip.protocol
        puerto_publico = segmento_transp.dstport
        ip_privada, puerto_privado = self.nat_entrante[(protocolo, puerto_publico)]
        mac_privada = self.mac_de(ip_privada)
        puerto_switch = self.puerto_por_ip.get(ip_privada)

        if mac_privada is None or puerto_switch is None:
            log_color(
                RED,
                f"No se puede reinstalar flujo entrante hacia {ip_privada}: MAC o puerto desconocidos",
            )
            return

        log_color(
            YELLOW,
            f"Flujo entrante expirado: reinstalo {datagrama_ip.srcip}:{segmento_transp.srcport} → "
            f"{PUBLIC_IP}:{puerto_publico} (conexión de {ip_privada}:{puerto_privado})",
        )

        fm_back = of.ofp_flow_mod()
        fm_back.idle_timeout = TIMEOUT
        fm_back.flags = of.OFPFF_SEND_FLOW_REM

        fm_back.match.in_port = PUBLIC_PORT
        fm_back.match.dl_type = 0x800
        fm_back.match.nw_src = datagrama_ip.srcip
        fm_back.match.nw_dst = PUBLIC_IP
        fm_back.match.nw_proto = protocolo
        fm_back.match.tp_src = segmento_transp.srcport
        fm_back.match.tp_dst = puerto_publico

        fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
        fm_back.actions.append(of.ofp_action_dl_addr.set_dst(mac_privada))
        fm_back.actions.append(of.ofp_action_nw_addr.set_dst(ip_privada))
        fm_back.actions.append(of.ofp_action_tp_port.set_dst(puerto_privado))
        fm_back.actions.append(of.ofp_action_output(port=puerto_switch))

        reglas = self.reglas_por_puerto.setdefault((protocolo, puerto_publico), set())
        clave = self.clave_regla(fm_back.match)
        if clave not in reglas:
            self.connection.send(fm_back)
            reglas.add(clave)

        # Reenviar el paquete actual (los siguientes pasan por la regla)
        msg = of.ofp_packet_out()
        msg.data = paquete.raw  # bytes originales: el switch aplica las acciones
        msg.actions = fm_back.actions
        self.connection.send(msg)

    def aprender_arp(self, ip, mac):
        self.tabla_arp[ip] = mac
        self.arp_visto[ip] = time.time()

    def mac_de(self, ip):
        # Devuelve la MAC de la IP, o None si no se conoce o la entrada venció
        if ip in self.tabla_arp and time.time() - self.arp_visto[ip] > ARP_TTL:
            log_color(YELLOW, f"Entrada ARP de {ip} vencida")
            del self.tabla_arp[ip]
            del self.arp_visto[ip]
        return self.tabla_arp.get(ip)

    def limpiar_espera(self):
        # Descarta los paquetes que llevan demasiado tiempo esperando un ARP Reply
        ahora = time.time()
        for ip, lista in list(self.paquetes_en_espera.items()):
            if ahora - lista[0]["tiempo"] > ARP_ESPERA_MAX:
                log_color(
                    RED,
                    f"ARP sin respuesta de {ip}: se descartan {len(lista)} paquete(s)",
                )
                del self.paquetes_en_espera[ip]

    def enviar_arp_request(self, ip_buscada):

        if ip_buscada.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            mac_src, ip_src, puerto = PRIVATE_MAC, PRIVATE_IP, of.OFPP_FLOOD
        else:
            mac_src, ip_src, puerto = PUBLIC_MAC, PUBLIC_IP, PUBLIC_PORT
        request = arp()
        request.opcode = arp.REQUEST
        request.hwsrc, request.protosrc = mac_src, ip_src
        request.hwdst, request.protodst = MAC_CERO, ip_buscada

        e = ethernet(type=ethernet.ARP_TYPE, src=mac_src, dst=MAC_BROADCAST)
        e.payload = request

        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=puerto))

        self.connection.send(msg)

    # parte 6.3:
    def obtener_puerto_publico(self, datagrama_ip, segmento_transp):
        protocolo = datagrama_ip.protocol
        if protocolo == ipv4.ICMP_PROTOCOL:
            return None
        ip_privada = datagrama_ip.srcip
        puerto_privado = segmento_transp.srcport

        clave_saliente = (protocolo, ip_privada, puerto_privado)

        # Si ya existía, recuperamos el puerto que le habíamos dado antes
        if clave_saliente in self.nat_saliente:
            return self.nat_saliente[clave_saliente]

        # Si no esta en el dicc de flujo saliente, le asignamos un puerto público
        if self.puertos_libres:
            # Reutilizamos el menor de los puertos liberados
            puerto_publico = min(self.puertos_libres)
            self.puertos_libres.remove(puerto_publico)

        elif self.siguiente_puerto_publico <= PUERTO_PUBLICO_MAX:
            # No hay liberados: usamos uno nuevo
            puerto_publico = self.siguiente_puerto_publico
            self.siguiente_puerto_publico += 1

        else:
            # Están todos en uso
            return None

        # Guardamos el viaje de ida
        self.nat_saliente[clave_saliente] = puerto_publico
        # Guardamos el viaje de vuelta (para cuando internet responda)
        self.nat_entrante[(protocolo, puerto_publico)] = (ip_privada, puerto_privado)

        log_color(
            GREEN,
            f"Nueva conexión PAT: {ip_privada}:{puerto_privado} -> {PUBLIC_IP}:{puerto_publico}",
        )
        return puerto_publico

    def clave_regla(self, match):
        # Identifica una regla por los campos de su match (el switch las distingue igual)
        return (
            match.in_port,
            match.nw_proto,
            match.nw_src,
            match.tp_src,
            match.nw_dst,
            match.tp_dst,
        )

    # parte 6.4:
    def instalar_flujos(
        self, packet, puerto_de_entrada, datagrama_ip, segmento_transp, puerto_publico
    ):
        mac_destino = self.tabla_arp[datagrama_ip.dstip]
        es_icmp = datagrama_ip.protocol == ipv4.ICMP_PROTOCOL
        if es_icmp:
            # Sin puerto público: no hay entrada en las tablas NAT ni estado que liberar
            reglas = set()
        else:
            reglas = self.reglas_por_puerto.setdefault(
                (datagrama_ip.protocol, puerto_publico), set()
            )

        # ----------------- FLUJO SALIENTE -----------------------
        # Instalar Flujo Saliente (consulta)
        fm = of.ofp_flow_mod()
        fm.idle_timeout = TIMEOUT  # time out flujo saliente
        if not es_icmp:
            fm.flags = (
                of.OFPFF_SEND_FLOW_REM
            )  # avisa al POX cuando el switch borre esta regla

        # Filtro Saliente
        # Los paquetes que tengan este "origen/destino" en sus headers es un flujo.
        fm.match.in_port = puerto_de_entrada  # puerto por donde entra el paquete
        fm.match.dl_type = 0x800  # IPv4
        fm.match.nw_src = datagrama_ip.srcip  # dirección IP(NetWork) de origen
        fm.match.nw_dst = datagrama_ip.dstip  # dirección IP(NetWork) de destino
        fm.match.nw_proto = datagrama_ip.protocol  # protocolo de capa de transporte
        if not es_icmp:
            fm.match.tp_src = segmento_transp.srcport  # puerto de transporte de origen
            fm.match.tp_dst = segmento_transp.dstport  # puerto de transporte de destino

        # Acción Saliente (de privado a público)
        fm.actions.append(
            of.ofp_action_dl_addr.set_src(PUBLIC_MAC)
        )  # cambiamos MAC_origen
        fm.actions.append(
            of.ofp_action_dl_addr.set_dst(mac_destino)
        )  # cambiamos MAC_destino
        fm.actions.append(
            of.ofp_action_nw_addr.set_src(PUBLIC_IP)
        )  # cambiamos ip origen. NO cambiamos ip destino
        if not es_icmp:
            fm.actions.append(
                of.ofp_action_tp_port.set_src(puerto_publico)
            )  # cambiamos puerto de origen
        fm.actions.append(
            of.ofp_action_output(port=PUBLIC_PORT)
        )  # sacamos el paquete por el puerto "port="

        clave_saliente = self.clave_regla(fm.match)
        if clave_saliente not in reglas:
            self.connection.send(
                fm
            )  # guardamos las reglas open-flow(match-action) en la tabla de flujos interna.
            reglas.add(clave_saliente)

        # ----------------- FLUJO ENTRANTE -----------------------

        # Instalar Flujo Entrante (respuesta)
        fm_back = of.ofp_flow_mod()
        fm_back.idle_timeout = TIMEOUT  # time out flujo entrante
        if not es_icmp:
            fm_back.flags = (
                of.OFPFF_SEND_FLOW_REM
            )  # avisa al POX cuando el switch borre esta regla

        # Filtro Entrante
        # Los paquetes que tengan este "origen/destino" en sus headers es un flujo.
        fm_back.match.in_port = PUBLIC_PORT  # puerto desde donde llega
        fm_back.match.dl_type = 0x800  # IPv4
        fm_back.match.nw_src = datagrama_ip.dstip  # nuevo inicio
        fm_back.match.nw_dst = PUBLIC_IP  # dirección IP(NetWork) de destino
        fm_back.match.nw_proto = (
            datagrama_ip.protocol
        )  # protocolo de capa de transporte
        if not es_icmp:
            fm_back.match.tp_src = (
                segmento_transp.dstport
            )  # puerto de transporte de origen
            fm_back.match.tp_dst = puerto_publico  # puerto de transporte de destino

        # Acción Entrante
        fm_back.actions.append(
            of.ofp_action_dl_addr.set_src(PRIVATE_MAC)
        )  # cambiamos el MAC_inicio
        fm_back.actions.append(
            of.ofp_action_dl_addr.set_dst(packet.src)
        )  # cambiamos el MAC_destino
        fm_back.actions.append(
            of.ofp_action_nw_addr.set_dst(datagrama_ip.srcip)
        )  # cambiamos ip destino, NO ip origen
        if not es_icmp:
            fm_back.actions.append(
                of.ofp_action_tp_port.set_dst(segmento_transp.srcport)
            )  # cambiamos puerto de destino
        fm_back.actions.append(
            of.ofp_action_output(port=puerto_de_entrada)
        )  # sacamos el paquete por el puerto "port="

        clave_entrante = self.clave_regla(fm_back.match)
        if clave_entrante not in reglas:
            self.connection.send(
                fm_back
            )  # guardamos las reglas open-flow(match-action) en la tabla de flujos interna.
            reglas.add(clave_entrante)

        # Reenviar paquete actual con MACs actualizadas (Los posteriores pasan por flujo)
        msg = of.ofp_packet_out()
        msg.data = packet.raw  # bytes originales: el switch aplica las acciones
        msg.actions = fm.actions
        log_color(
            CYAN,
            f"ENVIANDO: {datagrama_ip.srcip} → {datagrama_ip.dstip} | MAC: {PUBLIC_MAC} → {mac_destino} | Out Port: {PUBLIC_PORT}",
        )
        self.connection.send(msg)

        return


def launch():

    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
