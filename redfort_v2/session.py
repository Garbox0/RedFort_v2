import os
import shutil
import re
import datetime
import logging
from .utils import print_colored

BASE_DIR = os.getenv("BASE_DIR", "./reportes")
logger = logging.getLogger(__name__)

def create_session():
    """
    Crea un directorio de sesión en BASE_DIR/YYYY-MM-DD/HH-MM-SS[_descripcion]
    """
    os.makedirs(BASE_DIR, exist_ok=True)
    date_folder = datetime.datetime.now().strftime("%Y-%m-%d")
    date_dir = os.path.join(BASE_DIR, date_folder)
    os.makedirs(date_dir, exist_ok=True)
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
    Imprime todas las sesiones agrupadas por fecha YYYY-MM-DD.
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
    Devuelve lista de tuplas (ruta, etiqueta) para cada sesión.
    Etiqueta = YYYY-MM-DD/HH‑MM‑SS[_desc]
    """
    sessions = []
    date_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    for date_folder in sorted(os.listdir(BASE_DIR)):
        if not date_pattern.match(date_folder):
            continue
        for ses in sorted(os.listdir(os.path.join(BASE_DIR, date_folder))):
            sessions.append((
                os.path.join(BASE_DIR, date_folder, ses),
                f"{date_folder}/{ses}"
            ))
    return sessions

def delete_sessions():
    """
    Muestra sesiones numeradas y permite eliminar la seleccionada.
    """
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
    Menú inicial: elegir sesión, crear nueva o eliminar.
    Devuelve ruta de session_dir.
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
    """
    Guarda la salida de una herramienta en session_dir/{tool_name}.txt
    """
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
    Concatena todos los .txt de session_dir en consolidated_report.txt.
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