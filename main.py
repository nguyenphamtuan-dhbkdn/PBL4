from Data.models import init_db
from GUI.dashboard_integrated import run_gui

if __name__ == "__main__":
    init_db()
    run_gui()
