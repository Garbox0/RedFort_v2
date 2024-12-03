# REDFORT_v2

**RedFort** es una herramienta automatizada de pentesting diseñada para simplificar y agilizar diversas tareas de seguridad informática. Permite ejecutar herramientas populares como Nmap, Amass, Shodan, Nikto, Burp Suite, Metasploit y muchas más, todo dentro de un sistema organizado de sesiones para facilitar la recopilación y análisis de los resultados.

## Características

- **Enumeración Automatizada**: Ejecución de escaneos con Nmap, recopilación de subdominios con Amass y búsqueda de información en Shodan.
- **Escaneo de Vulnerabilidades Web**: Realiza análisis con herramientas como Nikto, WhatWeb, Gobuster, OWASP ZAP, Burp Suite, SQLmap, y XSStrike.
- **Generación de Payloads y Reverse Shells**: Crea payloads utilizando msfvenom y los guarda de manera organizada.
- **Explotación y Ataques**: Ejecuta herramientas como Metasploit, BeEF y Empire para realizar explotación y ataques avanzados.
- **Análisis de Seguridad en Aplicaciones Móviles**: Realiza pruebas de seguridad en aplicaciones móviles con MobSF y Drozer.
- **Auditoría de Redes Wi-Fi**: Realiza auditorías de redes Wi-Fi usando Aircrack-ng.
- **Análisis de Redes y MITM**: Realiza ataques MITM utilizando Ettercap.
- **Generación de Reportes Consolidado**: Crea reportes detallados de las actividades realizadas y guarda todos los resultados en un único archivo.
- **Gestión de Sesiones**: Los resultados se almacenan en un directorio único por sesión para facilitar su organización.

## Herramientas

**RedFort v2** integra las siguientes herramientas para realizar diversas tareas de pentesting y auditoría:

- **nmap**: Escaneo de redes y puertos.
- **amass**: Recolecta subdominios de un dominio objetivo.
- **shodan_search**: Obtiene información sobre una IP utilizando la API de Shodan.
- **nikto**: Escaneo de vulnerabilidades web.
- **whatweb**: Identificación de tecnologías web.
- **gobuster**: Escaneo de directorios y archivos ocultos en servidores web.
- **owasp_zap**: Escaneo de seguridad web utilizando la API de OWASP ZAP.
- **burp_suite**: Escaneo de seguridad web utilizando la API de Burp Suite.
- **sqlmap**: Escaneo de vulnerabilidades SQLi en sitios web.
- **xsstrike**: Escaneo de vulnerabilidades XSS.
- **metasploit**: Framework de explotación de vulnerabilidades.
- **beef**: Framework de explotación en ataques web (especialmente en ataques de ingeniería social).
- **empire**: Framework para la explotación de vulnerabilidades y ejecución de post-explotación.
- **mobsf**: Análisis de aplicaciones móviles.
- **drozer**: Análisis de seguridad en aplicaciones Android.
- **aircrack_ng**: Auditoría de redes Wi-Fi y crackeo de contraseñas.
- **ettercap**: Realización de ataques MITM (Man-In-The-Middle) en redes.
- **payload**: Generación de payloads utilizando msfvenom.
- **report**: Generación de reportes consolidados de la sesión.

## Instalación

Para instalar **RedFort v2**, simplemente clona este repositorio y ejecuta el script. El proceso de instalación puede tomar un tiempo dependiendo de las dependencias y herramientas que te falten. Asegúrate de tener permisos de superusuario para instalar las dependencias si es necesario.

### Paso 1: Clona el repositorio
```bash
git clone https://github.com/**TU_USUARIO**/RedFort_v2
cd RedFort_v2
```

### Paso 2: Otorga permisos de ejecución al script
```bash
chmod +x RedFort_v2.py
```

### Paso 3: Ejecuta el script
```bash
python3 RedFort_v2.py
```

### Dependencias necesarias

**RedFort v2** verifica automáticamente si las dependencias necesarias están instaladas en tu sistema. Si falta alguna herramienta, el script intentará instalarla automáticamente utilizando `apt`. Si alguna herramienta no se encuentra en tu sistema, se te pedirá que la instales manualmente.

### Crear una sesión

Al ejecutar el script, **RedFort v2** creará un directorio de sesión único basado en la fecha y hora actual para almacenar todos los resultados de las herramientas que ejecutes. Esto asegura que los resultados estén organizados y sean fáciles de acceder.

### Generación de reportes

Al finalizar el uso de las herramientas, puedes generar un reporte consolidado con todos los resultados de la sesión. Este reporte se guarda en el directorio de la sesión y te proporciona un resumen completo de todas las pruebas realizadas.
