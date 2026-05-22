# Instalación completa desde cero

Esta guía explica cómo instalar el collector NetFlow, el Excel, el dashboard web y la identificación DNS por dispositivo en un entorno nuevo, incluso si todavía no se conocen las IPs.

## 1. Identificar la red

En la PC donde va a correr Python, abrir PowerShell y ejecutar:

```powershell
ipconfig
```

Buscar el adaptador activo, normalmente `Ethernet` o `Wi-Fi`.

Anotar:

- `Dirección IPv4`: IP de la PC/servidor Python.
- `Puerta de enlace predeterminada`: IP del MikroTik.
- `Máscara de subred`: sirve para saber la red interna.

Ejemplo:

```text
Dirección IPv4 . . . . . . . . . . . : 192.168.1.114
Máscara de subred . . . . . . . . . : 255.255.255.0
Puerta de enlace predeterminada . . : 192.168.1.254
```

En ese ejemplo:

- PC/servidor Python: `192.168.1.114`
- MikroTik: `192.168.1.254`
- Red interna: `192.168.1.0/24`

Si no está claro cuál es el MikroTik, probar:

```powershell
Test-NetConnection 192.168.1.254 -Port 8728
```

También se puede entrar al router desde navegador o WinBox usando la puerta de enlace.

## 2. Preparar Windows

Instalar Python 3.11 o superior desde:

```text
https://www.python.org/
```

Durante la instalación marcar:

```text
Add python.exe to PATH
```

Verificar:

```powershell
python --version
pip --version
```

## 3. Instalar el proyecto

Copiar la carpeta del proyecto en la PC, por ejemplo:

```text
C:\netflow
```

Entrar a la carpeta:

```powershell
cd C:\netflow
```

Instalar dependencias:

```powershell
pip install -r requirements.txt
```

## 4. Crear archivo .env

Copiar `.env.example` como `.env`.

Editar `.env` con los datos reales detectados.

Ejemplo:

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

Reglas:

- `MIKROTIK_HOST`: puerta de enlace/MikroTik.
- `INTERNAL_NETWORKS`: red interna.
- `DJANGO_ALLOWED_HOSTS`: incluir la IP de la PC Python.
- No subir ni compartir `.env` porque contiene clave real.

## 5. Abrir firewall de Windows

Abrir PowerShell como administrador.

Permitir NetFlow UDP 2055:

```powershell
New-NetFirewallRule -DisplayName "NetFlow UDP 2055" -Direction Inbound -Protocol UDP -LocalPort 2055 -Action Allow
```

Permitir DNS Syslog UDP 5514:

```powershell
New-NetFirewallRule -DisplayName "MikroTik DNS Syslog UDP 5514" -Direction Inbound -Protocol UDP -LocalPort 5514 -Action Allow
```

Permitir dashboard Django TCP 8000:

```powershell
New-NetFirewallRule -DisplayName "NetFlow Dashboard TCP 8000" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
```

## 6. Configurar MikroTik API

Entrar al MikroTik por WinBox, WebFig o terminal.

Reemplazar `192.168.1.114` por la IP real de la PC Python.

Reemplazar `TU_CLAVE_SEGURA` por una clave nueva.

```routeros
/ip service set api disabled=no port=8728
/ip service set api address=192.168.1.114/32
/user group add name=api-read policy=read,api
/user add name=netflow_reader group=api-read password=TU_CLAVE_SEGURA
/user set netflow_reader address=192.168.1.114/32
```

Probar desde Windows:

```powershell
Test-NetConnection 192.168.1.254 -Port 8728
```

Resultado esperado:

```text
TcpTestSucceeded : True
```

## 7. Configurar MikroTik Traffic Flow

Reemplazar `192.168.1.114` por la IP real de la PC Python.

Por WinBox:

1. Ir a `IP -> Traffic Flow`.
2. Activar `Enabled`.
3. Ir a `Target`.
4. Configurar:
   - `Dst Address`: IP de la PC Python.
   - `Port`: `2055`
   - `Version`: `9`
   - `Template Refresh`: `20`
   - `Template Timeout`: `1800`

Por terminal:

```routeros
/ip traffic-flow set enabled=yes
/ip traffic-flow target add dst-address=192.168.1.114 port=2055 version=9 v9-template-refresh=20 v9-template-timeout=1800
```

## 8. Configurar DNS para identificar dispositivos

El objetivo es que las PCs usen el MikroTik como DNS y que el MikroTik mande logs DNS a Python.

En MikroTik:

```routeros
/ip dns set allow-remote-requests=yes
/ip dhcp-server network print
```

Buscar la red interna, por ejemplo `192.168.1.0/24`, y configurar DNS:

```routeros
/ip dhcp-server network set [find address=192.168.1.0/24] dns-server=192.168.1.254
```

Configurar logging DNS hacia Python:

```routeros
/system logging action add name=remotePython target=remote remote=192.168.1.114 remote-port=5514 remote-log-format=syslog syslog-time-format=bsd-syslog
/system logging add topics=dns,debug action=remotePython
```

Verificar:

```routeros
/system logging print
/system logging action print
```

Debe existir una regla con:

```text
topics=dns,debug action=remotePython
```

## 9. Probar DNS por dispositivo

Desde la PC Python:

```powershell
nslookup test-$([guid]::NewGuid()).com 192.168.1.254
```

En MikroTik:

```routeros
/log print where message~"test-"
```

Debe aparecer algo parecido a:

```text
dns query from 192.168.1.114: #123456 test-xxxx.com. A
```

Esa línea es importante porque contiene la IP del dispositivo.

Si solo aparecen líneas `dns,packet <dominio:A:ttl=ip>` sin `query from 192.168.1.x`, no se podrá identificar el dispositivo con precisión.

## 10. Ejecutar el collector

En PowerShell normal:

```powershell
cd C:\netflow
python main.py
```

Debe mostrar:

```text
Escuchando NetFlow en 0.0.0.0:2055 UDP
Escuchando DNS Syslog en 0.0.0.0:5514 UDP
```

Verificar puertos:

```powershell
Get-NetUDPEndpoint | Where-Object { $_.LocalPort -in 2055,5514 }
```

Debe aparecer:

```text
0.0.0.0  2055
0.0.0.0  5514
```

## 11. Ejecutar dashboard

Abrir otra consola:

```powershell
cd C:\netflow
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```

Entrar desde navegador:

```text
http://127.0.0.1:8000
http://IP-DE-LA-PC-PYTHON:8000
```

Ejemplo:

```text
http://192.168.1.114:8000
```

## 12. Nombrar dispositivos

Para que el Excel y dashboard sean claros:

1. Entrar a MikroTik.
2. Ir a `IP -> DHCP Server -> Leases`.
3. Seleccionar dispositivo.
4. Usar `Make Static`.
5. Completar `Comment`.

Ejemplos:

```text
PC Administración
Gerencia
Recepción
Notebook Soporte
```

La prioridad de nombres es:

1. Comment de MikroTik.
2. `active-host-name`.
3. `host-name`.
4. MAC.
5. IP.

También se puede editar `devices.csv` para forzar nombres y áreas.

## 13. Verificar archivos generados

El collector crea:

```text
data/netflow.db
data/reporte_trafico.xlsx
```

El Excel se actualiza cada 60 segundos.

Si el Excel está abierto, Windows puede bloquear la escritura. Cerrar Excel y esperar el próximo ciclo.

## 14. Problemas comunes

### No llegan flows

Verificar:

```powershell
Get-NetUDPEndpoint | Where-Object { $_.LocalPort -eq 2055 }
```

Verificar firewall UDP 2055.

Verificar Traffic Flow en MikroTik.

### MikroTik API no configurada

Revisar:

- existe `.env`
- `MIKROTIK_HOST`
- `MIKROTIK_USER`
- `MIKROTIK_PASSWORD`
- API habilitada en MikroTik
- puerto 8728 accesible

### DNS aparece como Sin identificar

Revisar que los logs tengan:

```text
dns query from 192.168.1.x
```

Si solo tienen:

```text
dns,packet <dominio:A:ttl=ip>
```

no incluyen IP de cliente.

### No se puede abrir el dashboard desde otra PC

Revisar:

- firewall TCP 8000
- `DJANGO_ALLOWED_HOSTS`
- ejecutar con `0.0.0.0:8000`

## 15. Seguridad

- No usar usuario admin para API si no es necesario.
- Usar usuario de solo lectura.
- Restringir API a la IP de la PC Python.
- No abrir API hacia internet.
- No subir `.env`.
- No subir bases reales con tráfico de clientes.
- Usar contraseñas únicas.
