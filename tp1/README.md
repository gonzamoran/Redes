# Trabajo Práctivo N°1: File Transfer. 

Implementacion de una aplicacion de capa red de arquitectura cliente-servidor con un protocolo RDT sobre UDP.

Grupo 6:

- [Bentiez, Gonzalo](https://github.com/gonzalo-benitez)
- [Gutierrez, Gaspar](https://github.com/GGutierrez34)
- [Moran, Gonzalo](https://github.com/gonzamoran)
- [Visca, Julian](https://github.com/jvisca)
- [Wallace, Simon](https://github.com/simoonw4)

## Servidor

Para consultar las opciones:

```
    python3 start-server.py -h
```

El servidor se levanta con: 

```
    python3 start-server.py  [ - H ADDR ] [ - p PORT ] [- s DIRPATH ]
```

#### Ejemplo 
Este ejemplo usa los valores default definidos para la direccion y el puerto. 
Ejemplos para usar con mininet:
```
    python3 start-server.py -H 10.0.0.1 -p 12000 -s server_storage/
```

## Cliente

### Carga

Para consultar los parametros:

```
    python3 upload.py -h
```

Se necesita lo siguiente:

```
upload  upload [ - h ] [ - v | -q ] [ - H ADDR ] [ - p PORT ] [ - s FILEPATH ] [ - n FILENAME ] [ - r protocol ]
```

#### Ejemplo:

Siguiendo ejemplo para mininet
```
python3 upload.py -H 10.0.0.1 -p 12000 -s /lib/common/sack.py -n sack_cargado.py -r sack -v

```

### Descarga

Para consultar los parametros:

```
    python3 download.py -h
```

Se necesita lo siguiente:

```
download [ - h ] [ - v | -q ] [ - H ADDR ] [ - p PORT ] [ - d FILEPATH ] [ - n FILENAME ] [ - r protocol ]
```

#### Ejemplo:

Siguiendo ejemplo para mininet
```
python3 upload.py -H 10.0.0.1 -p 12000 -d descarga_protocolo_sack.py -n server_storage/sack_cargado.py -r sack -v

```

## Mininet

Para usar emular una red con un RTT de 40ms y una perdida del 10%:

```
sudo mn --topo single,5 --link tc,delay=10ms,loss=5
```

### xterm

Dentro de mininet abrir hosts:

```
xterm h1 h2
```

Dentro de cada terminal de los host levantar un servidor y clientes en cada uno.

Para cerrar mininet usar:

```
exit
```