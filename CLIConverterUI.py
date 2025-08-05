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
        self.root.title("SonicWall CLI Converter v2.0")
        
        # Setup logging for troubleshooting
        self.setup_logging()
        self.logger.info("Application started")
        
        # Application version and metadata
        self.version = "2.0"
        self.author = "Network Admin Tools"
        self.last_updated = "2025-01-05"

        # Define allowed zones and regex patterns
        self.allowed_zones = {"WAN", "LAN", "MDT", "CLIENT LAN", "SYSINT", "SYSEXT", "SYSCLIENT", "DMZ"}
        self.ip_regex = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        self.network_regex = r"^((\d{1,3}\.){3}\d{1,3})/(3[0-2]|[12]?\d)$"
        self.fqdn_regex = r"(?=^.{4,253}$)(^(\*\.)?((?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\.)+[a-zA-Z]{2,63}$)"
        self.ip_with_subnet_regex = r"^((\d{1,3}\.){3}\d{1,3}) ((\d{1,3}\.){3}\d{1,3})$"
        self.cidr_regex = r"^((\d{1,3}\.){3}\d{1,3})/(3[0-2]|[12]?\d)$"

        # Global fields for SRNumber and GroupName
        global_frame = tk.Frame(root)
        global_frame.pack(pady=10)
        
        tk.Label(global_frame, text="SR Number:").grid(row=0, column=0, padx=5, sticky='e')
        self.global_sr_number = tk.StringVar()
        sr_global_entry = tk.Entry(global_frame, textvariable=self.global_sr_number, width=20)
        sr_global_entry.grid(row=0, column=1, padx=5)

        self.global_group_name = tk.StringVar()
        group_global_entry = tk.Entry(global_frame, textvariable=self.global_group_name, width=20)
        group_global_entry.grid(row=0, column=3, padx=5)

        tk.Label(global_frame, text="Group Name:").grid(row=0, column=2, padx=5, sticky='e')

        # Combined frame for headers and entries
        self.main_entry_frame = tk.Frame(root)
        self.main_entry_frame.pack(pady=10)
        
        # Header row in the same frame as entries
        tk.Label(self.main_entry_frame, text="Name", font=('Arial', 9, 'bold')).grid(row=0, column=0, padx=5, sticky='w')
        tk.Label(self.main_entry_frame, text="IPAddress", font=('Arial', 9, 'bold')).grid(row=0, column=1, padx=5, sticky='w')
        tk.Label(self.main_entry_frame, text="Subnet", font=('Arial', 9, 'bold')).grid(row=0, column=2, padx=5, sticky='w')
        tk.Label(self.main_entry_frame, text="Zone", font=('Arial', 9, 'bold')).grid(row=0, column=3, padx=5, sticky='w')
        tk.Label(self.main_entry_frame, text="Action", font=('Arial', 9, 'bold')).grid(row=0, column=4, padx=5, sticky='w')

        # Track the next row for entries
        self.next_row = 1

        self.entries = []
        self.entry_frame = self.main_entry_frame
        self.create_entry()  # Initialize with one entry set

        # Button Frame
        button_frame = tk.Frame(root)
        button_frame.pack(pady=10)

        self.add_entry_btn = tk.Button(button_frame, text="Add Entry", command=self.create_entry)
        self.add_entry_btn.pack(side=tk.LEFT, padx=5)

        # Upload button
        self.upload_btn = tk.Button(button_frame, text="Upload TXT File", command=self.upload_txt_file)
        self.upload_btn.pack(side=tk.LEFT, padx=5)

        # Buttons
        self.convert_btn = tk.Button(button_frame, text="Convert to CLI", command=self.convert_to_cli)
        self.convert_btn.pack(side=tk.LEFT, padx=5)

        self.save_btn = tk.Button(button_frame, text="Save CLI Output", command=self.save_output, state=tk.DISABLED)
        self.save_btn.pack(side=tk.LEFT, padx=5)

        # Text Area
        self.output_text = tk.Text(root, width=80, height=20)
        self.output_text.pack(pady=20)

        self.csv_file_path = None
        self.cli_output = ""

    def setup_logging(self):
        """Setup logging for troubleshooting and debugging"""
        # Create logs directory if it doesn't exist
        log_dir = os.path.join(os.path.dirname(__file__), 'logs')
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        # Setup logger
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

    def cidr_to_subnet_mask(self, cidr):
        """Convert CIDR notation to dotted decimal subnet mask"""
        self.logger.debug(f"Converting CIDR {cidr} to subnet mask")
        try:
            cidr_int = int(cidr)
            if cidr_int < 0 or cidr_int > 32:
                self.logger.warning(f"Invalid CIDR value: {cidr}")
                return None
            
            # Create subnet mask
            mask = (0xffffffff >> (32 - cidr_int)) << (32 - cidr_int)
            subnet_mask = f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"
            self.logger.debug(f"CIDR {cidr} converted to {subnet_mask}")
            return subnet_mask
        except ValueError as e:
            self.logger.error(f"Error converting CIDR {cidr}: {e}")
            return None
    
    def is_fqdn(self, value):
        """Check if a value is likely an FQDN"""
        # Check if it contains dots and letters but no spaces
        if '.' in value and any(c.isalpha() for c in value) and ' ' not in value:
            # Check if it matches FQDN pattern
            return re.match(self.fqdn_regex, value) is not None
        return False

    def create_entry(self):
        entry_vars = {
            'Name': tk.StringVar(),
            'IPAddress': tk.StringVar(),
            'Subnet': tk.StringVar(),
            'Zone': tk.StringVar()
        }
        
        # Create entry directly in main frame
        row = self.next_row
        self.next_row += 1
        
        # Name entry
        name_entry = tk.Entry(self.main_entry_frame, textvariable=entry_vars['Name'], width=20)
        name_entry.grid(row=row, column=0, padx=5, pady=2)
        
        # IPAddress entry
        ip_entry = tk.Entry(self.main_entry_frame, textvariable=entry_vars['IPAddress'], width=20)
        ip_entry.grid(row=row, column=1, padx=5, pady=2)
        
        # Subnet entry
        subnet_entry = tk.Entry(self.main_entry_frame, textvariable=entry_vars['Subnet'], width=20)
        subnet_entry.grid(row=row, column=2, padx=5, pady=2)

        # Zone dropdown (read-only)
        zone_combo = ttk.Combobox(self.main_entry_frame, textvariable=entry_vars['Zone'], width=13, state="readonly")
        zone_combo['values'] = list(self.allowed_zones)
        zone_combo.grid(row=row, column=3, padx=5, pady=2)

        # Remove button
        remove_btn = tk.Button(self.main_entry_frame, text="Remove", command=lambda: self.remove_entry(row, entry_vars))
        remove_btn.grid(row=row, column=4, padx=5, pady=2)

        entry_vars['row'] = row
        entry_vars['widgets'] = [name_entry, ip_entry, subnet_entry, zone_combo, remove_btn]
        self.entries.append(entry_vars)
        
    def remove_entry(self, row, entry_vars):
        if len(self.entries) > 1:  # Keep at least one entry
            # Remove all widgets for this entry
            for widget in entry_vars['widgets']:
                widget.destroy()
            self.entries.remove(entry_vars)

    def upload_txt_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    data = file.readlines()
                    self.populate_fields_from_txt(data)
                messagebox.showinfo("Success", "Fields populated successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file: {e}")

    def populate_fields_from_txt(self, data):
        # Check if first entry has data
        has_existing_data = False
        if self.entries:
            first_entry = self.entries[0]
            if (first_entry['Name'].get().strip() or 
                first_entry['IPAddress'].get().strip() or 
                first_entry['Subnet'].get().strip() or 
                first_entry['Zone'].get().strip()):
                has_existing_data = True
        
        # Only clear entries if there's no existing data
        if not has_existing_data:
            self.entries = []  # Clear existing entries
            # Clear the entry frame content
            for widget in self.main_entry_frame.winfo_children():
                if widget.grid_info()['row'] != 0:  # Skip header row
                    widget.destroy()

        # Filter out empty lines
        clean_data = [line.strip() for line in data if line.strip()]
        
        i = 0
        while i < len(clean_data):
            # Look for name line (contains spaces and letters)
            if ' ' in clean_data[i] and any(c.isalpha() for c in clean_data[i]):
                name_line = clean_data[i]
                name = ' '.join(name_line.split()[1:])  # Take everything after the first word (zone)
                
                # Next line should be IP/subnet
                if i + 1 < len(clean_data):
                    ip_subnet_line = clean_data[i + 1]
                    
                    # Parse IP and subnet
                    if '/' in ip_subnet_line:
                        ip, cidr_or_subnet = ip_subnet_line.split('/', 1)
                        # Check if it's CIDR notation or already a subnet mask
                        if cidr_or_subnet.isdigit():
                            # Convert CIDR to subnet mask
                            subnet = self.cidr_to_subnet_mask(cidr_or_subnet)
                            if subnet is None:
                                subnet = "255.255.255.255"  # Default if conversion fails
                        else:
                            subnet = cidr_or_subnet
                    else:
                        ip = ip_subnet_line
                        # Check if it's an FQDN
                        if self.is_fqdn(ip):
                            subnet = ""  # FQDNs don't need subnet masks
                        else:
                            subnet = "255.255.255.255"  # Default for host
                    
                    # Next line should be zone
                    if i + 2 < len(clean_data):
                        zone = clean_data[i + 2]
                        
                        # Skip number and IPv4 lines if they exist
                        skip_lines = 0
                        if i + 3 < len(clean_data) and clean_data[i + 3].isdigit():
                            skip_lines += 1
                        if i + 3 + skip_lines < len(clean_data) and clean_data[i + 3 + skip_lines].upper() == 'IPV4':
                            skip_lines += 1
                        
                        entry_vars = {
                            "Name": tk.StringVar(value=name),
                            "IPAddress": tk.StringVar(value=ip),
                            "Subnet": tk.StringVar(value=subnet),
                            "Zone": tk.StringVar(value=zone)
                        }
                        
                        self.create_entry_with_vars(entry_vars)
                        i += 3 + skip_lines
                    else:
                        i += 1
                else:
                    i += 1
            else:
                i += 1

        # Refresh entries
        self.root.update_idletasks()

    def create_entry_with_vars(self, entry_vars):
        # Create entry directly in main frame using same system as create_entry
        row = self.next_row
        self.next_row += 1
        
        # Name entry
        name_entry = tk.Entry(self.main_entry_frame, textvariable=entry_vars['Name'], width=20)
        name_entry.grid(row=row, column=0, padx=5, pady=2)
        
        # IPAddress entry
        ip_entry = tk.Entry(self.main_entry_frame, textvariable=entry_vars['IPAddress'], width=20)
        ip_entry.grid(row=row, column=1, padx=5, pady=2)
        
        # Subnet entry
        subnet_entry = tk.Entry(self.main_entry_frame, textvariable=entry_vars['Subnet'], width=20)
        subnet_entry.grid(row=row, column=2, padx=5, pady=2)

        # Zone dropdown (read-only)
        zone_combo = ttk.Combobox(self.main_entry_frame, textvariable=entry_vars['Zone'], width=13, state="readonly")
        zone_combo['values'] = list(self.allowed_zones)
        zone_combo.grid(row=row, column=3, padx=5, pady=2)

        # Remove button
        remove_btn = tk.Button(self.main_entry_frame, text="Remove", command=lambda: self.remove_entry(row, entry_vars))
        remove_btn.grid(row=row, column=4, padx=5, pady=2)

        entry_vars['row'] = row
        entry_vars['widgets'] = [name_entry, ip_entry, subnet_entry, zone_combo, remove_btn]
        self.entries.append(entry_vars)

    def convert_to_cli(self):
        try:
            self.cli_output = "configure\n"
            address_objects = []
            
            # Get global values
            sr_number_main = self.global_sr_number.get().strip()
            group_name = self.global_group_name.get().strip()
            
            for entry_vars in self.entries:
                name = entry_vars['Name'].get().strip()
                ip_address = entry_vars['IPAddress'].get().strip()
                subnet = entry_vars['Subnet'].get().strip()
                zone = entry_vars['Zone'].get().strip().upper()
                
                # Skip empty rows
                if not ip_address:
                    continue
                    
                if not zone or zone not in self.allowed_zones:
                    messagebox.showerror("Error", f"Zone must be one of: {', '.join(self.allowed_zones)}")
                    return
                
                # Validate formats
                valid_ip = re.match(self.ip_regex, ip_address)
                valid_subnet = re.match(self.ip_regex, subnet)
                valid_fqdn = re.match(self.fqdn_regex, ip_address)

                if not (valid_ip or valid_fqdn):
                    messagebox.showerror("Error", f"Invalid IP/FQDN format for {ip_address}")
                    return

                if subnet and not valid_subnet:
                    messagebox.showerror("Error", f"Invalid subnet mask for {subnet}")
                    return

                # Create object name
                object_name = name if name else f"{sr_number_main} Auto-Generated"
                
                # Handle different IP/subnet formats
                if valid_ip:
                    if subnet != "255.255.255.255":
                        self.cli_output += f'address-object ipv4 "{object_name}" network {ip_address} {subnet} zone {zone}\n'
                    else:
                        self.cli_output += f'address-object ipv4 "{object_name}" host {ip_address} zone {zone}\n'
                elif valid_fqdn:
                    self.cli_output += f'address-object fqdn "{object_name}" domain {ip_address} zone {zone}\n'
                
                address_objects.append(object_name)
            
            self.cli_output += "commit\n"
            
            # Add address group if group name is provided and there are multiple objects
            if group_name and len(address_objects) > 1:
                group_full_name = f"{group_name} {sr_number_main}" if sr_number_main else group_name
                self.cli_output += f'address-group ipv4 "{group_full_name}"\n'
                for obj_name in address_objects:
                    self.cli_output += f'address-object ipv4 "{obj_name}"\n'
                self.cli_output += "exit\n"
                self.cli_output += "commit\n"
                
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, self.cli_output)
            self.save_btn.config(state=tk.NORMAL)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def save_output(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    file.write(self.cli_output)
                messagebox.showinfo("Success", "CLI output saved successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CLIConverter(root)
    root.mainloop()

