# Collector NetFlow MikroTik con Excel y Dashboard

Herramienta local para recibir NetFlow v9 desde MikroTik, guardar historial en SQLite, generar un Excel administrativo y visualizar estadísticas por dispositivo en Django.

## Estructura

- `main.py`: collector UDP NetFlow, sincronización MikroTik API, SQLite y Excel.
- `manage.py`: entrada del dashboard Django.
- `web_dashboard/`: visualizador web.
- `devices.csv`: nombres y áreas manuales opcionales.
- `.env.example`: formato de configuración local.
- `data/netflow.db`: base SQLite usada por collector y dashboard.
- `data/reporte_trafico.xlsx`: Excel generado por el collector.
- `docs/mikrotik_api_connection.txt`: guía para habilitar y probar API MikroTik.
- `docs/instalacion_completa_desde_cero.md`: instalación completa en un entorno nuevo.

## Instalación

Usar Python 3.11 o superior.

```powershell
pip install -r requirements.txt
```

Si Windows responde que `python` no se reconoce, instalar Python desde `python.org` y marcar `Add python.exe to PATH`.

## Configuración local

Copiar `.env.example` como `.env` y editar valores locales:

```env
MIKROTIK_HOST=192.168.1.254
MIKROTIK_PORT=8728
MIKROTIK_USER=netflow_reader
MIKROTIK_PASSWORD=CAMBIAR_ESTA_CLAVE
MIKROTIK_USE_SSL=false
INTERNAL_NETWORKS=192.168.1.0/24
DASHBOARD_ENABLED=true
DJANGO_SECRET_KEY=change-me-local-only
DJANGO_DEBUG=true
DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost,192.168.1.114
DATABASE_PATH=data/netflow.db
EXCEL_PATH=data/reporte_trafico.xlsx
DNS_SYSLOG_ENABLED=true
DNS_SYSLOG_HOST=0.0.0.0
DNS_SYSLOG_PORT=5514
```

No subir `.env` al repositorio. Debe quedar solo en la máquina local.

## Ejecutar collector NetFlow

```powershell
python main.py
```

El collector:

- escucha NetFlow v9 en `0.0.0.0:2055/UDP`
- escucha DNS Syslog en `0.0.0.0:5514/UDP`
- guarda flows en `data/netflow.db`
- sincroniza nombres desde DHCP Leases de MikroTik
- actualiza `data/reporte_trafico.xlsx` cada 60 segundos
- sigue funcionando aunque el dashboard no esté corriendo

## Ejecutar dashboard Django

En otra consola:

```powershell
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```

Entrar desde el navegador:

- `http://127.0.0.1:8000`
- `http://192.168.1.114:8000`

El dashboard es solo visualizador y exportador. Lee la misma base `data/netflow.db` sin duplicar datos.

## Configurar MikroTik Traffic Flow

En RouterOS:

1. Ir a `IP -> Traffic Flow`.
2. Activar `Enabled`.
3. Ir a `Target`.
4. Configurar:
   - `Dst Address`: `192.168.1.114`
   - `Port`: `2055`
   - `Version`: `9`
   - `Template Refresh`: `20`
   - `Template Timeout`: `1800`

## Habilitar MikroTik API

Seguir la guía:

`docs/mikrotik_api_connection.txt`

Comandos por terminal MikroTik:

```routeros
/ip service set api disabled=no port=8728
/ip service set api address=192.168.1.114/32
/user group add name=api-read policy=read,api
/user add name=netflow_reader group=api-read password=TU_CLAVE_SEGURA
/user set netflow_reader address=192.168.1.114/32
```

Resumen:

- habilitar `IP -> Services -> api`
- usar puerto `8728`
- crear usuario de solo lectura
- restringir acceso a `192.168.1.114`
- no exponer API hacia internet

## Nombrar dispositivos

En RouterOS:

1. Ir a `IP -> DHCP Server -> Leases`.
2. Seleccionar dispositivo.
3. Usar `Make Static`.
4. Completar `Comment`, por ejemplo `PC Administración`, `Gerencia`, `Recepción`.

## Identificación de dispositivos

Prioridad para nombre de dispositivo:

1. comment de MikroTik
2. `active-host-name`
3. `host-name`
4. MAC
5. IP

`devices.csv` también se carga. Si una IP tiene un nombre manual definido en `devices.csv`, ese nombre se usa para forzar una etiqueta administrativa.

## Identificación de destinos

Prioridad para destino:

1. DNS correlation si existe una tabla `dns_queries`
2. reverse DNS desde cache local
3. ASN si está disponible en futuras integraciones
4. IP only

Si no hay datos DNS todavía, NetFlow sigue funcionando. El dashboard mostrará IP o reverse DNS cuando exista.

## DNS logging MikroTik

Tu MikroTik debe enviar los logs DNS al servidor Python en UDP `5514`.

Configuración esperada en RouterOS:

```routeros
/system logging action add name=remotePython target=remote remote=192.168.1.114 remote-port=5514 remote-log-format=syslog syslog-time-format=bsd-syslog
/system logging add topics=dns action=remotePython
```

Verificación:

```routeros
/system logging print
/system logging action print
```

En Windows debe existir una regla de firewall para UDP `5514`.

## Dashboard

Páginas incluidas:

- `/`: resumen general con tarjetas, tops y gráficos
- `/devices/`: dispositivos con búsqueda y ordenamiento
- `/devices/<ip>/`: detalle por dispositivo
- `/traffic/`: tráfico identificado con filtros
- `/dns/`: DNS por dispositivo si hay datos disponibles
- `/exports/`: descargas de Excel y CSV

## Excel

El archivo se genera en:

```text
data/reporte_trafico.xlsx
```

Si queda abierto en Excel, Windows puede bloquear la escritura. El collector seguirá funcionando y avisará en consola hasta que se cierre el archivo.

## Seguridad

- No subir `.env`.
- No escribir claves reales en README ni en el código.
- No subir bases reales con tráfico de clientes, como `data/netflow.db`.
- No usar usuario admin de MikroTik si no es necesario.
- Usar usuario API solo lectura.
- Restringir API por IP.
- No abrir el puerto `8728` desde internet.
