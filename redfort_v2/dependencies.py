import subprocess
import sys

def check_and_install_dependencies():
    """Instala automáticamente CLI y librerías Python (vía apt) en entornos Debian/Ubuntu/Kali."""
    # 1) Herramientas CLI
    cli_deps = [
        "figlet", "nmap", "amass", "shodan", "nikto",
        "gobuster", "whatweb", "aircrack-ng", "ettercap",
        "hydra", "hashcat", "theharvester", "msfvenom"
    ]
    for pkg in cli_deps:
        if subprocess.call(["which", pkg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            print(f"[CLI] {pkg} no encontrado. Instalando con apt…")
            subprocess.run(["apt", "update"], stdout=subprocess.DEVNULL)
            subprocess.run(["apt", "install", "-y", pkg], check=True)

    # 2) Librerías Python (paquetes Debian)
    py_deps = {
        "python-dotenv":   ("python3-dotenv",   "dotenv"),
        "pyfiglet":        ("python3-pyfiglet",  "pyfiglet"),
        "shodan":          ("python3-shodan",    "shodan"),
        "validators":      ("python3-validators","validators"),
        "requests":        ("python3-requests",  "requests")
    }
    for pip_name, (apt_name, module_name) in py_deps.items():
        try:
            __import__(module_name)
        except ImportError:
            print(f"[PYPI] {pip_name} no encontrado. Instalando {apt_name} con apt…")
            subprocess.run(["apt", "update"], stdout=subprocess.DEVNULL)
            subprocess.run(["apt", "install", "-y", apt_name], check=True)