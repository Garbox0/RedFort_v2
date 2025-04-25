import os
import subprocess
import logging
import validators

logger = logging.getLogger(__name__)

def print_colored(text, color="red"):
    """
    Imprime texto coloreado en terminal.
    """
    colors = {
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "reset": "\033[0m"
    }
    print(f"{colors.get(color, colors['red'])}{text}{colors['reset']}")

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
    """
    Limpia la pantalla (cls en Windows, clear en UNIX).
    """
    os.system("cls" if os.name == "nt" else "clear")

def safe_run(command, **kwargs):
    """
    Ejecuta un comando de forma segura, captura stdout/stderr y maneja excepciones.
    """
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