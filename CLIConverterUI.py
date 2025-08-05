import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import csv
import re
import logging
from datetime import datetime
import os

class CLIConverter:
    """
    SonicWall CLI Converter v2.1 - Main Application Class
    
    This class provides a GUI interface for converting SonicWall network objects
    (address and service objects) from text files or manual entry into properly
    formatted CLI commands for SonicWall devices.
    
    Features:
    - Address object conversion with IP/CIDR/FQDN support
    - Service object conversion with protocol and port support
    - Mixed format file parsing (handles IPv4 type indicators and separators)
    - Group creation for both address and service objects
    - Comprehensive input validation and error handling
    - Detailed logging for troubleshooting
    
    Troubleshooting:
    - Check logs/ directory for detailed error messages
    - Ensure input files follow the expected 5-line format for addresses
    - Verify zones and protocols are in the allowed lists
    """
    
    def __init__(self, root):
        """
        Initialize the CLI Converter application.
        
        Args:
            root: Tkinter root window object
        """
        self.root = root
        self.root.title("SonicWall CLI Converter v2.1")

        # Setup logging for troubleshooting
        self.setup_logging()
        self.logger.info("Application started")
        
        # Application version and metadata
        self.version = "2.1"
        self.author = "Network Admin Tools"
        self.last_updated = "2025-08-05"

        # Define allowed zones and regex patterns for address objects
        self.allowed_zones = {"WAN", "LAN", "MDT", "CLIENT LAN", "SYSINT", "SYSEXT", "SYSCLIENT", "DMZ", "NOC"}
        self.ip_regex = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        self.network_regex = r"^((\d{1,3}\.){3}\d{1,3})/(3[0-2]|[12]?\d)$"
        self.fqdn_regex = r"(?=^.{4,253}$)(^(\*\.)?((?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\.)+[a-zA-Z]{2,63}$)"
        self.ip_with_subnet_regex = r"^((\d{1,3}\.){3}\d{1,3}) ((\d{1,3}\.){3}\d{1,3})$"
        self.cidr_regex = r"^((\d{1,3}\.){3}\d{1,3})/(3[0-2]|[12]?\d)$"
        
        # Define allowed protocols for service objects
        self.allowed_protocols = {"IGMP", "TCP", "ICMP", "UDP", "6over4", "GRE", "ESP", "AH", "ICMPv6", "EIGRP", "OSPF", "PIM", "L2TP"}

        # Create tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=1, fill='both', padx=10, pady=10)

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
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            handlers=[
                logging.FileHandler(log_filename),
                logging.StreamHandler()  # Also log to console for debugging
            ]
        )

        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Logging initialized. Log file: {log_filename}")

    def setup_address_tab(self):
        """Setup Address Object/Group tab"""
        # Global fields frame
        global_frame = tk.Frame(self.address_tab)
        global_frame.pack(pady=10, fill='x')
        
        tk.Label(global_frame, text="SR Number:").grid(row=0, column=0, padx=5, sticky='e')
        self.global_sr_number = tk.StringVar()
        sr_entry = tk.Entry(global_frame, textvariable=self.global_sr_number, width=20)
        sr_entry.grid(row=0, column=1, padx=5)
        
        tk.Label(global_frame, text="Group Name:").grid(row=0, column=2, padx=5, sticky='e')
        self.global_group_name = tk.StringVar()
        group_entry = tk.Entry(global_frame, textvariable=self.global_group_name, width=20)
        group_entry.grid(row=0, column=3, padx=5)
        
        # Main entry frame
        self.main_address_frame = tk.Frame(self.address_tab)
        self.main_address_frame.pack(pady=10, fill='both', expand=True)
        
        # Headers
        tk.Label(self.main_address_frame, text="Name", font=('Arial', 9, 'bold')).grid(row=0, column=0, padx=5, sticky='w')
        tk.Label(self.main_address_frame, text="IP Address", font=('Arial', 9, 'bold')).grid(row=0, column=1, padx=5, sticky='w')
        tk.Label(self.main_address_frame, text="Subnet", font=('Arial', 9, 'bold')).grid(row=0, column=2, padx=5, sticky='w')
        tk.Label(self.main_address_frame, text="Zone", font=('Arial', 9, 'bold')).grid(row=0, column=3, padx=5, sticky='w')
        tk.Label(self.main_address_frame, text="Action", font=('Arial', 9, 'bold')).grid(row=0, column=4, padx=5, sticky='w')
        
        self.next_address_row = 1
        self.address_entries = []
        
        # Button frame
        button_frame = tk.Frame(self.address_tab)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Add Entry", command=self.create_address_entry).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Upload TXT File", command=self.upload_address_txt).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Convert to CLI", command=self.convert_address_to_cli).pack(side=tk.LEFT, padx=5)
        self.save_address_btn = tk.Button(button_frame, text="Save CLI Output", command=self.save_address_output, state=tk.DISABLED)
        self.save_address_btn.pack(side=tk.LEFT, padx=5)
        
        # Output area
        self.address_output = tk.Text(self.address_tab, width=80, height=15)
        self.address_output.pack(pady=10, fill='both', expand=True)
        
        # Initialize with one entry
        self.create_address_entry()
        
        # Store CLI output
        self.address_cli_output = ""

    def setup_service_tab(self):
        """Setup Service Object/Group tab"""
        # Global fields frame
        global_frame = tk.Frame(self.service_tab)
        global_frame.pack(pady=10, fill='x')
        
        tk.Label(global_frame, text="SR Number:").grid(row=0, column=0, padx=5, sticky='e')
        self.service_sr_number = tk.StringVar()
        sr_entry = tk.Entry(global_frame, textvariable=self.service_sr_number, width=20)
        sr_entry.grid(row=0, column=1, padx=5)
        
        tk.Label(global_frame, text="Group Name:").grid(row=0, column=2, padx=5, sticky='e')
        self.service_group_name = tk.StringVar()
        group_entry = tk.Entry(global_frame, textvariable=self.service_group_name, width=20)
        group_entry.grid(row=0, column=3, padx=5)
        
        # Main entry frame
        self.main_service_frame = tk.Frame(self.service_tab)
        self.main_service_frame.pack(pady=10, fill='both', expand=True)
        
        # Headers
        tk.Label(self.main_service_frame, text="Name", font=('Arial', 9, 'bold')).grid(row=0, column=0, padx=5, sticky='w')
        tk.Label(self.main_service_frame, text="Protocol", font=('Arial', 9, 'bold')).grid(row=0, column=1, padx=5, sticky='w')
        tk.Label(self.main_service_frame, text="Port Start", font=('Arial', 9, 'bold')).grid(row=0, column=2, padx=5, sticky='w')
        tk.Label(self.main_service_frame, text="Port End", font=('Arial', 9, 'bold')).grid(row=0, column=3, padx=5, sticky='w')
        tk.Label(self.main_service_frame, text="Zone", font=('Arial', 9, 'bold')).grid(row=0, column=4, padx=5, sticky='w')
        tk.Label(self.main_service_frame, text="Action", font=('Arial', 9, 'bold')).grid(row=0, column=5, padx=5, sticky='w')
        
        self.next_service_row = 1
        self.service_entries = []
        
        # Button frame
        button_frame = tk.Frame(self.service_tab)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Add Entry", command=self.create_service_entry).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Upload TXT File", command=self.upload_service_txt).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Convert to CLI", command=self.convert_service_to_cli).pack(side=tk.LEFT, padx=5)
        self.save_service_btn = tk.Button(button_frame, text="Save CLI Output", command=self.save_service_output, state=tk.DISABLED)
        self.save_service_btn.pack(side=tk.LEFT, padx=5)
        
        # Output area
        self.service_output = tk.Text(self.service_tab, width=80, height=15)
        self.service_output.pack(pady=10, fill='both', expand=True)
        
        # Initialize with one entry
        self.create_service_entry()
        
        # Store CLI output
        self.service_cli_output = ""

    def create_address_entry(self):
        """Add a new address entry row"""
        entry_data = {'row': self.next_address_row}

        # Name Entry
        name_var = tk.StringVar()
        name_entry = tk.Entry(self.main_address_frame, textvariable=name_var, width=20)
        name_entry.grid(row=self.next_address_row, column=0, padx=5)
        entry_data['name'] = name_var
        entry_data['name_widget'] = name_entry

        # IP Address Entry
        ip_var = tk.StringVar()
        ip_entry = tk.Entry(self.main_address_frame, textvariable=ip_var, width=15)
        ip_entry.grid(row=self.next_address_row, column=1, padx=5)
        entry_data['ip'] = ip_var
        entry_data['ip_widget'] = ip_entry

        # Subnet Entry
        subnet_var = tk.StringVar()
        subnet_entry = tk.Entry(self.main_address_frame, textvariable=subnet_var, width=15)
        subnet_entry.grid(row=self.next_address_row, column=2, padx=5)
        entry_data['subnet'] = subnet_var
        entry_data['subnet_widget'] = subnet_entry

        # Zone Dropdown
        zone_var = tk.StringVar()
        zone_combo = ttk.Combobox(self.main_address_frame, textvariable=zone_var, 
                                  values=list(self.allowed_zones), width=12, state="readonly")
        zone_combo.grid(row=self.next_address_row, column=3, padx=5)
        entry_data['zone'] = zone_var
        entry_data['zone_widget'] = zone_combo

        # Remove Button
        remove_btn = tk.Button(self.main_address_frame, text="Remove", command=lambda: self.remove_entry(entry_data))
        remove_btn.grid(row=self.next_address_row, column=4, padx=5)
        entry_data['remove_btn'] = remove_btn

        self.address_entries.append(entry_data)
        self.next_address_row += 1

    def remove_entry(self, entry_data):
        """Remove the entry row"""
        for widget in entry_data.values():
            if hasattr(widget, 'grid_forget'):
                widget.grid_forget()
        self.address_entries.remove(entry_data)

    def create_service_entry(self):
        """Add a new service entry row"""
        entry_data = {'row': self.next_service_row}

        # Name Entry
        name_var = tk.StringVar()
        name_entry = tk.Entry(self.main_service_frame, textvariable=name_var, width=20)
        name_entry.grid(row=self.next_service_row, column=0, padx=5)
        entry_data['name'] = name_var
        entry_data['name_widget'] = name_entry

        # Protocol Dropdown
        protocol_var = tk.StringVar()
        protocol_combo = ttk.Combobox(self.main_service_frame, textvariable=protocol_var, 
                                     values=list(self.allowed_protocols), width=10, state="readonly")
        protocol_combo.grid(row=self.next_service_row, column=1, padx=5)
        entry_data['protocol'] = protocol_var
        entry_data['protocol_widget'] = protocol_combo

        # Port Start Entry
        port_start_var = tk.StringVar()
        port_start_entry = tk.Entry(self.main_service_frame, textvariable=port_start_var, width=10)
        port_start_entry.grid(row=self.next_service_row, column=2, padx=5)
        entry_data['port_start'] = port_start_var
        entry_data['port_start_widget'] = port_start_entry

        # Port End Entry
        port_end_var = tk.StringVar()
        port_end_entry = tk.Entry(self.main_service_frame, textvariable=port_end_var, width=10)
        port_end_entry.grid(row=self.next_service_row, column=3, padx=5)
        entry_data['port_end'] = port_end_var
        entry_data['port_end_widget'] = port_end_entry

        # Zone Dropdown
        zone_var = tk.StringVar()
        zone_combo = ttk.Combobox(self.main_service_frame, textvariable=zone_var, 
                                  values=list(self.allowed_zones), width=12, state="readonly")
        zone_combo.grid(row=self.next_service_row, column=4, padx=5)
        entry_data['zone'] = zone_var
        entry_data['zone_widget'] = zone_combo

        # Remove Button
        remove_btn = tk.Button(self.main_service_frame, text="Remove", command=lambda: self.remove_service_entry(entry_data))
        remove_btn.grid(row=self.next_service_row, column=5, padx=5)
        entry_data['remove_btn'] = remove_btn

        self.service_entries.append(entry_data)
        self.next_service_row += 1

    def remove_service_entry(self, entry_data):
        """Remove the service entry row"""
        for widget in entry_data.values():
            if hasattr(widget, 'grid_forget'):
                widget.grid_forget()
        self.service_entries.remove(entry_data)

    # Address object functionality methods
    def upload_address_txt(self):
        """
        Upload and parse address objects from a TXT file.
        
        Supports multiple file formats:
        1. Standard 4-line format: Name, IP, Subnet, Zone
        2. Mixed 5-line format: IPv4, Name, IP/Subnet, Zone, Number
        
        Troubleshooting:
        - "list index out of range": Check file format, ensure complete entries
        - "Zone not in allowed list": Use supported zones or update allowed_zones
        - "Failed to load file": Check file encoding (UTF-8) and format
        
        File Format Example (Mixed):
        IPv4
        Server_Name
        192.168.1.10/255.255.255.255
        LAN
        2
        """
        filename = filedialog.askopenfilename(
            title="Select Address Objects TXT",
            filetypes=(('Text Files', '*.txt'),)
        )
        if not filename:
            return  # User canceled file selection

        try:
            with open(filename, 'r', encoding='utf-8') as file:
                lines = file.readlines()
                
                # Clean lines and remove line numbers if present
                cleaned_lines = []
                for line in lines:
                    line = line.strip()
                    if line:  # Skip empty lines
                        # Remove line numbers if present (format: "123|content")
                        if '|' in line and line.split('|')[0].isdigit():
                            line = '|'.join(line.split('|')[1:])  # Remove first part before |
                        cleaned_lines.append(line)
                
                # Clear existing entries except the first one (keep one empty entry)
                entries_to_remove = self.address_entries[1:]  # Keep first entry
                for entry in entries_to_remove:
                    self.remove_entry(entry)

                # Parse file in groups of 4 lines (Name, IP, Subnet, Zone)
                count = 0
                self.logger.info(f"Processing {len(cleaned_lines)} cleaned lines from file")
                for line_idx, line in enumerate(cleaned_lines):
                    self.logger.debug(f"Line {line_idx}: '{line}'")
                
                i = 0
                while i < len(cleaned_lines):
                    # Ensure we have at least 5 lines remaining for the 5-line format
                    if i + 4 >= len(cleaned_lines):
                        break
                        
                    try:
                        # Handle 5-line format: IPv4, Name, IP/Subnet, Zone, Number
                        if cleaned_lines[i].strip().upper() == 'IPV4':
                            # This is the expected 5-line format
                            type_indicator = cleaned_lines[i].strip()
                            name_line = cleaned_lines[i + 1].strip()
                            ip = cleaned_lines[i + 2].strip()
                            zone = cleaned_lines[i + 3].strip()
                            separator = cleaned_lines[i + 4].strip()  # This should be a number
                            
                            self.logger.debug(f"Found IPv4 entry: type='{type_indicator}', name='{name_line}', ip='{ip}', zone='{zone}', sep='{separator}'")
                            
                            # Process this entry and move to next
                            i += 5  # Skip all 5 lines of this entry
                        else:
                            # Skip lines that don't start with IPv4
                            i += 1
                            continue
                    except IndexError as ie:
                        self.logger.error(f"Index error at line {i}: {str(ie)}")
                        break
                    
                    # Handle case where IP and subnet are combined (e.g., "103.141.202.156/255.255.255.255")
                    subnet = ""
                    if '/' in ip:
                        # Split IP/subnet combination
                        ip_parts = ip.split('/')
                        if len(ip_parts) == 2:
                            ip = ip_parts[0]
                            subnet = ip_parts[1]
                    
                    # Skip if essential fields are empty (subnet can be empty for single hosts)
                    if not name_line or not ip or not zone:
                        continue
                    
                    # Validate zone is in allowed list
                    if zone not in self.allowed_zones:
                        self.logger.warning(f"Zone '{zone}' not in allowed list, skipping entry '{name_line}'")
                        continue
                    
                    self.logger.debug(f"Parsing entry {count + 1}: name='{name_line}', ip='{ip}', subnet='{subnet}', zone='{zone}'")
                    
                    # Use first entry if it's empty, otherwise create new
                    if count == 0 and len(self.address_entries) == 1:
                        # Update the existing first entry
                        self.address_entries[0]['name'].set(name_line)
                        self.address_entries[0]['ip'].set(ip)
                        self.address_entries[0]['subnet'].set(subnet)
                        self.address_entries[0]['zone'].set(zone)
                    else:
                        # Create new entry
                        self.create_address_entry()
                        self.address_entries[-1]['name'].set(name_line)
                        self.address_entries[-1]['ip'].set(ip)
                        self.address_entries[-1]['subnet'].set(subnet)
                        self.address_entries[-1]['zone'].set(zone)
                    
                    count += 1
                    self.logger.info(f"Loaded address: {name_line} ({ip} {subnet} {zone})")
                        
                messagebox.showinfo("Success", f"Loaded {count} address objects from file.")
                
        except Exception as e:
            self.logger.error(f"Failed to load file: {str(e)}")
            messagebox.showerror("Error", f"Failed to load file: {str(e)}")

    def convert_address_to_cli(self):
        """Convert address objects to SonicWall CLI commands"""
        try:
            # Get global variables
            sr_number = self.global_sr_number.get().strip()
            group_name = self.global_group_name.get().strip()
            
            # Collect valid entries
            valid_entries = []
            for entry in self.address_entries:
                name = entry['name'].get().strip()
                ip = entry['ip'].get().strip()
                subnet = entry['subnet'].get().strip()
                zone = entry['zone'].get().strip()
                
                # Skip empty entries
                if not name or not ip or not zone:
                    continue
                    
                # Validate IP format
                if not self.validate_ip_format(ip, subnet):
                    messagebox.showerror("Validation Error", f"Invalid IP format for '{name}': {ip} {subnet}")
                    return
                    
                valid_entries.append({
                    'name': name,
                    'ip': ip,
                    'subnet': subnet,
                    'zone': zone
                })
            
            if not valid_entries:
                messagebox.showwarning("Warning", "No valid address entries found to convert.")
                return
            
            # Generate CLI commands
            cli_commands = self.generate_address_cli_commands(valid_entries, sr_number, group_name)
            
            # Display output
            self.address_output.delete(1.0, tk.END)
            self.address_output.insert(tk.END, cli_commands)
            
            # Store for saving
            self.address_cli_output = cli_commands
            self.save_address_btn.config(state=tk.NORMAL)
            
            self.logger.info(f"Generated CLI commands for {len(valid_entries)} address objects")
            messagebox.showinfo("Success", f"Generated CLI commands for {len(valid_entries)} address objects")
            
        except Exception as e:
            self.logger.error(f"Error converting addresses to CLI: {str(e)}")
            messagebox.showerror("Error", f"Error converting addresses to CLI: {str(e)}")
    
    def validate_ip_format(self, ip, subnet):
        """Validate IP address format"""
        if not ip:
            return False
            
        # Check for different formats
        if re.match(self.ip_regex, ip):  # Single IP
            return True
        elif re.match(self.network_regex, ip):  # CIDR notation
            return True
        elif re.match(self.fqdn_regex, ip):  # FQDN
            return True
        elif subnet and re.match(self.ip_regex, ip) and re.match(self.ip_regex, subnet):  # IP with subnet mask
            return True
        
        return False
    
    def generate_address_cli_commands(self, entries, sr_number, group_name):
        """
        Generate SonicWall CLI commands for address objects.
        
        Creates properly formatted CLI commands based on address type:
        - Host: Single IP address
        - Network with mask: IP with subnet mask
        - Network CIDR: IP with CIDR notation
        - FQDN: Fully qualified domain name
        
        Args:
            entries: List of address object dictionaries
            sr_number: Service request number for documentation
            group_name: Optional group name to create address group
            
        Returns:
            String containing formatted CLI commands
            
        Troubleshooting:
        - Ensure all entries have valid IP formats
        - Check that zones exist in SonicWall configuration
        - Verify object names don't contain special characters
        """
        commands = []
        
        # Add header comment
        if sr_number:
            commands.append(f"! SR Number: {sr_number}")
        commands.append(f"! Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        commands.append(f"! Total address objects: {len(entries)}")
        commands.append("!")
        commands.append("configure")
        commands.append("!")
        
        # Generate individual address object commands
        for entry in entries:
            name = entry['name']
            ip = entry['ip']
            subnet = entry['subnet']
            zone = entry['zone']
            
            # Determine address type and format command accordingly
            if re.match(self.network_regex, ip):  # CIDR notation
                commands.append(f'address-object ipv4 "{name}" network {ip} zone "{zone}"')
            elif re.match(self.fqdn_regex, ip):  # FQDN
                commands.append(f'address-object ipv4 "{name}" fqdn {ip} zone "{zone}"')
            elif subnet and re.match(self.ip_regex, subnet):  # IP with subnet mask
                commands.append(f'address-object ipv4 "{name}" network {ip} mask {subnet} zone "{zone}"')
            else:  # Single host IP
                commands.append(f'address-object ipv4 "{name}" host {ip} zone "{zone}"')
        
        # Add address group if group name is provided
        if group_name:
            commands.append("!")
            commands.append(f'address-group ipv4 "{group_name}" zone "{entries[0]["zone"]}"')
            for entry in entries:
                commands.append(f'  address-object ipv4 "{entry["name"]}"')
            commands.append("exit")
        
        commands.append("!")
        commands.append("commit")
        commands.append("exit")
        
        return "\n".join(commands)

    def save_address_output(self):
        """Save address CLI output to file"""
        if not self.address_cli_output:
            messagebox.showwarning("Warning", "No CLI output to save. Please convert addresses first.")
            return
            
        filename = filedialog.asksaveasfilename(
            title="Save Address CLI Commands",
            defaultextension=".txt",
            filetypes=(('Text Files', '*.txt'), ('All Files', '*.*'))
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as file:
                    file.write(self.address_cli_output)
                messagebox.showinfo("Success", f"CLI commands saved to {filename}")
                self.logger.info(f"Address CLI commands saved to {filename}")
            except Exception as e:
                self.logger.error(f"Error saving file: {str(e)}")
                messagebox.showerror("Error", f"Error saving file: {str(e)}")

    def upload_service_txt(self):
        """
        Upload and parse service objects from a TXT file.
        
        Expected format (4 lines per service):
        - Service Name
        - Protocol (TCP, UDP, ICMP, etc.)
        - Port Start
        - Port End
        
        Troubleshooting:
        - "Protocol not in allowed list": Check supported protocols or update allowed_protocols
        - "Invalid port range": Ensure ports are 1-65535 and start <= end
        - "No valid service entries": Check file format and required fields
        
        File Format Example:
        HTTP_Service
        TCP
        80
        80
        """
        filename = filedialog.askopenfilename(
            title="Select Service Objects TXT",
            filetypes=(('Text Files', '*.txt'),)
        )
        if not filename:
            return  # User canceled file selection

        try:
            with open(filename, 'r', encoding='utf-8') as file:
                lines = file.readlines()
                
                # Clean lines and remove line numbers if present
                cleaned_lines = []
                for line in lines:
                    line = line.strip()
                    if line:  # Skip empty lines
                        # Remove line numbers if present (format: "123|content")
                        if '|' in line and line.split('|')[0].isdigit():
                            line = '|'.join(line.split('|')[1:])  # Remove first part before |
                        cleaned_lines.append(line)
                
                # Clear existing entries except the first one (keep one empty entry)
                entries_to_remove = self.service_entries[1:]  # Keep first entry
                for entry in entries_to_remove:
                    self.remove_service_entry(entry)

                # Parse file in groups of 5 lines (number + 4 data lines) or 4 lines (just data)
                count = 0
                self.logger.info(f"Processing {len(cleaned_lines)} cleaned lines from file")
                for line_idx, line in enumerate(cleaned_lines):
                    self.logger.debug(f"Line {line_idx}: '{line}'")
                
                # Parse the mixed format manually - first entry has no number, rest are numbered
                count = 0
                i = 0
                
                while i < len(cleaned_lines):
                    # Ensure we have at least 4 lines remaining
                    if i + 3 >= len(cleaned_lines):
                        break
                        
                    try:
                        # Check if this looks like a service entry (4 consecutive lines)
                        name_line = cleaned_lines[i].strip()
                        protocol = cleaned_lines[i + 1].strip()
                        port_start = cleaned_lines[i + 2].strip()
                        port_end = cleaned_lines[i + 3].strip()
                        
                        # Skip if this looks like a number separator
                        if (name_line.isdigit() and len(name_line) <= 2):
                            # This is a number separator, skip it and get the actual service data
                            i += 1  # Skip the number
                            # Check if we still have enough lines after skipping
                            if i + 3 >= len(cleaned_lines):
                                break
                            name_line = cleaned_lines[i].strip()
                            protocol = cleaned_lines[i + 1].strip()
                            port_start = cleaned_lines[i + 2].strip()
                            port_end = cleaned_lines[i + 3].strip()
                    except IndexError as ie:
                        self.logger.error(f"Index error at line {i}: {str(ie)}")
                        break
                    
                    self.logger.debug(f"Parsing entry {count + 1}: name='{name_line}', protocol='{protocol}', start='{port_start}', end='{port_end}'")
                    
                    # Skip if any required field is empty
                    if not name_line or not protocol or not port_start or not port_end:
                        i += 4
                        continue
                    
                    # Validate protocol is in allowed list
                    if protocol not in self.allowed_protocols:
                        self.logger.warning(f"Protocol '{protocol}' not in allowed list, skipping entry '{name_line}'")
                        i += 4
                        continue

                    # Use first entry if it's empty, otherwise create new
                    if count == 0 and len(self.service_entries) == 1:
                        # Update the existing first entry
                        self.service_entries[0]['name'].set(name_line)
                        self.service_entries[0]['protocol'].set(protocol)
                        self.service_entries[0]['port_start'].set(port_start)
                        self.service_entries[0]['port_end'].set(port_end)
                    else:
                        # Create new entry
                        self.create_service_entry()
                        self.service_entries[-1]['name'].set(name_line)
                        self.service_entries[-1]['protocol'].set(protocol)
                        self.service_entries[-1]['port_start'].set(port_start)
                        self.service_entries[-1]['port_end'].set(port_end)
                    
                    count += 1
                    self.logger.info(f"Loaded service: {name_line} ({protocol} {port_start}-{port_end})")
                    
                    # Move to next service entry
                    i += 4  # Move past the 4 lines we just processed
                        
                messagebox.showinfo("Success", f"Loaded {count} service objects from file.")
                
        except Exception as e:
            self.logger.error(f"Failed to load file: {str(e)}")
            messagebox.showerror("Error", f"Failed to load file: {str(e)}")

    def convert_service_to_cli(self):
        """Convert service objects to SonicWall CLI commands"""
        try:
            # Get global variables
            sr_number = self.service_sr_number.get().strip()
            group_name = self.service_group_name.get().strip()
            
            # Collect valid entries
            valid_entries = []
            for entry in self.service_entries:
                name = entry['name'].get().strip()
                protocol = entry['protocol'].get().strip()
                port_start = entry['port_start'].get().strip()
                port_end = entry['port_end'].get().strip()
                zone = entry['zone'].get().strip()
                
                # Skip empty entries
                if not name or not protocol or not port_start:
                    continue
                    
                # Validate protocol
                if protocol not in self.allowed_protocols:
                    messagebox.showerror("Validation Error", f"Invalid protocol for '{name}': {protocol}")
                    return
                    
                # Validate ports
                if not self.validate_ports(port_start, port_end):
                    messagebox.showerror("Validation Error", f"Invalid port range for '{name}': {port_start}-{port_end}")
                    return
                    
                valid_entries.append({
                    'name': name,
                    'protocol': protocol,
                    'port_start': port_start,
                    'port_end': port_end if port_end else port_start,
                    'zone': zone
                })
            
            if not valid_entries:
                messagebox.showwarning("Warning", "No valid service entries found to convert.")
                return
            
            # Generate CLI commands
            cli_commands = self.generate_service_cli_commands(valid_entries, sr_number, group_name)
            
            # Display output
            self.service_output.delete(1.0, tk.END)
            self.service_output.insert(tk.END, cli_commands)
            
            # Store for saving
            self.service_cli_output = cli_commands
            self.save_service_btn.config(state=tk.NORMAL)
            
            self.logger.info(f"Generated CLI commands for {len(valid_entries)} service objects")
            messagebox.showinfo("Success", f"Generated CLI commands for {len(valid_entries)} service objects")
            
        except Exception as e:
            self.logger.error(f"Error converting services to CLI: {str(e)}")
            messagebox.showerror("Error", f"Error converting services to CLI: {str(e)}")
    
    def validate_ports(self, port_start, port_end):
        """Validate port numbers"""
        try:
            start = int(port_start)
            if port_end:
                end = int(port_end)
                return 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end
            else:
                return 1 <= start <= 65535
        except ValueError:
            return False
    
    def generate_service_cli_commands(self, entries, sr_number, group_name):
        """
        Generate SonicWall CLI commands for service objects.
        
        Creates CLI commands based on protocol and port configuration:
        - TCP/UDP: Single port or port range
        - ICMP: Protocol only
        - Other protocols: Protocol specification
        
        Args:
            entries: List of service object dictionaries
            sr_number: Service request number for documentation
            group_name: Optional group name to create service group
            
        Returns:
            String containing formatted CLI commands
            
        Troubleshooting:
        - Verify protocol names match SonicWall supported protocols
        - Check port ranges are valid (1-65535)
        - Ensure service names are unique
        """
        commands = []
        
        # Add header comment
        if sr_number:
            commands.append(f"! SR Number: {sr_number}")
        commands.append(f"! Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        commands.append(f"! Total service objects: {len(entries)}")
        commands.append("!")
        commands.append("configure")
        commands.append("!")
        
        # Generate individual service object commands
        for entry in entries:
            name = entry['name']
            protocol = entry['protocol'].lower()
            port_start = entry['port_start']
            port_end = entry['port_end']
            
            # Format command based on protocol and port range
            if protocol in ['tcp', 'udp']:
                if port_start == port_end:
                    # Single port
                    commands.append(f'service-object "{name}" protocol {protocol} destination {port_start}')
                else:
                    # Port range
                    commands.append(f'service-object "{name}" protocol {protocol} destination {port_start} to {port_end}')
            elif protocol == 'icmp':
                # ICMP service
                commands.append(f'service-object "{name}" protocol icmp')
            else:
                # Other protocols (GRE, ESP, etc.)
                commands.append(f'service-object "{name}" protocol {protocol}')
        
        # Add service group if group name is provided
        if group_name:
            commands.append("!")
            commands.append(f'service-group "{group_name}"')
            for entry in entries:
                commands.append(f'  service-object "{entry["name"]}"')
            commands.append("exit")
        
        commands.append("!")
        commands.append("commit")
        commands.append("exit")
        
        return "\n".join(commands)

    def save_service_output(self):
        """Save service CLI output to file"""
        if not self.service_cli_output:
            messagebox.showwarning("Warning", "No CLI output to save. Please convert services first.")
            return
            
        filename = filedialog.asksaveasfilename(
            title="Save Service CLI Commands",
            defaultextension=".txt",
            filetypes=(('Text Files', '*.txt'), ('All Files', '*.*'))
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as file:
                    file.write(self.service_cli_output)
                messagebox.showinfo("Success", f"CLI commands saved to {filename}")
                self.logger.info(f"Service CLI commands saved to {filename}")
            except Exception as e:
                self.logger.error(f"Error saving file: {str(e)}")
                messagebox.showerror("Error", f"Error saving file: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CLIConverter(root)
    root.mainloop()

