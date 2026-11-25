"""
Topología de mininet para el TP1 (File Transfer).

Estrella con un switch: h1 es el servidor y h2..hN son clientes.
Usamos un switch porque en mininet se usan conexiones de punto a punto, por lo que solo podriamos
hacer una conexion con 1 solo cliente. Con el switch podemos tener mas de un cliente.

La pérdida se configura solo en el enlace del servidor (h1 - s1). Como todo
camino cliente <-> servidor cruza ese enlace una vez por sentido, la pérdida
total del camino en cada sentido es `loss` (lo que pide el enunciado).

El delay se aplica en todos los enlaces, en cada sentido, así que el RTT
entre un cliente y el servidor es 4 * delay (delay=10ms -> RTT = 40 ms).
"""

from mininet.link import TCLink
from mininet.topo import Topo


# Utilizamos TCL como link porque si usamos el link predeterminado no podriamos emular las pérdidas y delay.
class TopologiaTP(Topo):

    def build(self, clientes=2, loss=10, delay="10ms"):
        switch = self.addSwitch("s1")

        servidor = self.addHost("h1")
        self.addLink(servidor, switch, cls=TCLink, loss=loss, delay=delay)

        for i in range(clientes):
            cliente = self.addHost(f"h{i + 2}")
            self.addLink(cliente, switch, cls=TCLink, delay=delay)


topos = {"tp": TopologiaTP}  # Alias para el comando
