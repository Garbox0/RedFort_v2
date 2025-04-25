import logging
import os
from dotenv import load_dotenv
from .session      import select_or_create_session, prune_old_sessions, list_sessions, generate_report
from .menu         import print_header, print_help, print_menu, recon_menu, vuln_menu, web_menu, exploit_menu, mobile_menu, network_menu
from .utils        import clear, print_colored
from .dependencies import check_and_install_dependencies
from .tools        import generate_payload

load_dotenv()

# Asegurarnos de que exista el directorio de reportes antes de configurar el log
BASE_DIR = os.getenv("BASE_DIR", "./reportes")
os.makedirs(BASE_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    filename=os.path.join(BASE_DIR, "redfort.log")
)

def main():
    check_and_install_dependencies()
    prune_old_sessions(days=30)

    print("Sesiones existentes:")
    list_sessions()
    session_dir = select_or_create_session()

    while True:
        clear()
        print_header()
        print_menu()
        choice = input("Selecciona una opción: ").strip().lower()

        if choice == "h":
            clear()
            print_header()
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
    main()