import pyfiglet
from .utils   import clear, print_colored, input_non_empty
from .tools   import *
from .session import create_session, delete_sessions, generate_report

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

# ——— Menú Principal (sin pausa) ———
def print_menu():
    """Muestra las opciones del menú principal."""
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
            scan_map = {"1": "default", "2": "quick", "3": "stealth", "4": "detailed"}
            scan_type = scan_map.get(modo, "default")
            target = input_non_empty("IP o dominio (o 0 para volver): ")
            if target == "0":
                continue
            run_nmap(target, scan_type, session_dir)

        elif opt == "2":
            # Amass
            domain = input_non_empty("Dominio (o 0 para volver): ")
            if domain == "0":
                continue
            run_amass(domain, session_dir)

        elif opt == "3":
            # Shodan
            ip = input_non_empty("IP o dominio (o 0 para volver): ")
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