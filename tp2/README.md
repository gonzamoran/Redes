# Trabajo Práctico 2: SDN / NAT

### Grupo 6:

- [Benitez, Gonzalo](https://github.com/gonzalo-benitez)
- [Gutierrez, Gaspar](https://github.com/GGutierrez34)
- [Moran, Gonzalo](https://github.com/gonzamoran)
- [Visca, Julian](https://github.com/jvisca)
- [Wallace, Simon](https://github.com/simoonw4)

### Ejecución del controlador

Desde una terminal, ejecutar:  
`python3 pox/pox.py [log.level --DEBUG] protorouter`

### Ejecución de la topología

En otra terminal, ejecutar:  
`sudo python3 topo.py`

### Orden de ejecución recomendado

- Iniciar el controlador POX.
- Ejecutar la topología en Mininet.
- Verificar que el switch se conecte al controlador.

### Verificación básica

- Iniciar la red.
- Desde la CLI de Mininet:
    - Probar conectividad: `h2 ping h1`