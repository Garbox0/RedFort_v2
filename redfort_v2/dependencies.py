import sys
import subprocess

def check_and_install_dependencies():
    """Instala CLI y libs Python si faltan."""
    # 1) CLI
    cli_deps = [
        "figlet","nmap","amass","shodan","nikto",
        "gobuster","whatweb","aircrack-ng","ettercap",
        "hydra","hashcat","theHarvester","msfvenom"
    ]
    for pkg in cli_deps:
        if subprocess.call(["which", pkg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            print(f"{pkg} no encontrado. Instalando…")
            subprocess.run(["sudo","apt","install","-y",pkg], check=True)

    # 2) Python
    py_deps = ["python-dotenv","pyfiglet","shodan","validators","requests"]
    for pkg in py_deps:
        name = pkg.replace("-", "_")
        try:
            __import__(name)
        except ImportError:
            print(f"{pkg} no encontrado. Instalando…")
            subprocess.run([sys.executable,"-m","pip","install",pkg], check=True)