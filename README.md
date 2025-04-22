# Real-time-Network-Traffic-Dashboard

Este proyecto nos ayudará a practicar usando Python y Streamlkit para crear un Dashboard con nuestro trafico de red.


## Este proyecto esta basado en un tutorial de [freeCodeCamp.org](https://www.freecodecamp.org/news/build-a-real-time-network-traffic-dashboard-with-python-and-streamlit/)


## Prerequisitos
- Python 3.8 o una version mas reciente
- Conocimientos basicos de los conceptos de redes
- Familiaridad programando con Python
- Conocimiento basico de tecnicas y librerias para la visualizacion de datos

## Informacion
Si quieres conocer el paso a paso de como construir la aplicacion desde cero visita el archivo de `steps.md`

## Instalacion

- Ingresa a la carpeta `/network-dashboard`
- Crea un entorno virtual e instala el `requirements.txt`

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```


## Ejecucion
Ejecuta el siguiente comando:

```bash
streamlit run dashboard.py
```


## Funcionamiento

### Paso 1 

Da click en Start Capture

Nota: Puedes seleccionar diferentes interfaces de red

![Start Capture](/network-dashboard/capturas/1.png)

### Paso 2

Se te mostrara sin paquetes esto porque no entraste a ningun sitio web o no estas lanzando un telnet o un ping, para que te muestre paquetes recibidos puedes ingresar a una pagina, en mi caso Youtube y debes dar click al boton de actualizar.

![Network Traffic](/network-dashboard/capturas/2.png)


### Paso 3

SUna vez ingresando a una pagina o lanzando un ping y de que hayas actualizado, te debera mostrar la siguiente tabla.

![Network Traffic](/network-dashboard/capturas/4.png)

En esta tabla encontraras los datos capturados de los ultimos 10 paquetes.



### Explicacion de las graficas

En esta grafica se valida los protocolos por los que estan llegando los paquetes

![Network Traffic](/network-dashboard/capturas/5.png)


Aqui podemos ver los paquetes por segundo y las ip's

![Network Traffic](/network-dashboard/capturas/6.png)



### Simular Trafico

Tambien puedes simular el trafico para tener mas opciones en las graficas, al darle click al boton de simular trafico puedes ver como los datos se actualizan y las graficas cambian.

![Network Traffic](/network-dashboard/capturas/7.png)