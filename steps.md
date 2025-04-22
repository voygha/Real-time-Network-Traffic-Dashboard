# Inicializacion del proyecto

Para este proyecto estoy usando linux, por lo cual algunos comandos pueden cambiar dependiendo el sistema operativo o la distribucion de linux que tengas.


Creemos las siguientes carpetas:

- Abrimos una terminal:


```bash
mkdir network-dashboard
cd network-dashboard
```


## requirements.txt
Creamos el requirements.txt

con el siguiente contenido:

streamlit
pandas
scapy
plotly

## Entorno Virtual
Vamos a crear un entorno virtual e instalar el requirements.txt

Ejecutamos los siguientes comandos:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Hasta este punto ya tienes instaladas las librerias que utilizaremos

Debes tener una salida similar a esto:

![Inicializacion del Proyecto](/network-dashboard/capturas/image.png)
