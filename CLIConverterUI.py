import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import csv
import re
import logging
from datetime import datetime
import os

class CLIConverter:
    def __init__(self, root):
        self.root = root
        self.root.title("SonicWall CLI Converter v2.1")

        # Setup logging for troubleshooting
        self.setup_logging()
        self.logger.info("Application started")

        # Create tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=1, fill='both')

        # Address Object Tab
        self.address_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.address_tab, text='Address Object/Group')
        self.setup_address_tab()

        # Service Object Tab
        self.service_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.service_tab, text='Service Object/Group')
        self.setup_service_tab()

    def setup_logging(self):
        log_dir = os.path.join(os.path.dirname(__file__), 'logs')
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        log_filename = os.path.join(log_dir, f'sonicwall_cli_converter_{datetime.now().strftime("%Y%m%d")}.log')

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            handlers=[
                logging.FileHandler(log_filename),
                logging.StreamHandler()  # Also log to console for debugging
            ]
        )

        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Logging initialized. Log file: {log_filename}")

    def setup_address_tab(self):
        # Setup for Address Object/Group
        pass

    def setup_service_tab(self):
        # Setup for Service Object/Group
        pass

if __name__ == "__main__":
    root = tk.Tk()
    app = CLIConverter(root)
    root.mainloop()

