# SonicWall CLI Converter UI - User Manual

## Table of Contents
1. [Introduction](#introduction)
2. [Features](#features)
3. [Installation](#installation)
4. [User Interface Overview](#user-interface-overview)
5. [Usage Instructions](#usage-instructions)
6. [Input Formats](#input-formats)
7. [Troubleshooting](#troubleshooting)
8. [FAQ](#faq)

## Introduction

The SonicWall CLI Converter UI is a Python-based graphical application that automates the conversion of network address objects into SonicWall CLI commands. This tool is designed for network administrators who need to quickly generate CLI commands for SonicWall firewalls from structured data.

### Key Benefits
- **Time Saving**: Converts multiple address objects in seconds
- **Error Reduction**: Validates input data before conversion
- **Batch Processing**: Upload TXT files for mass conversion
- **Comprehensive Logging**: Detailed logs for troubleshooting

## Features

### Core Functionality
- **Manual Entry**: Direct input of address objects through the GUI
- **File Upload**: Import structured TXT files to auto-populate entries
- **CIDR Support**: Handles both CIDR notation (/24) and dotted decimal subnet masks
- **FQDN Support**: Processes fully qualified domain names
- **Zone Validation**: Ensures zones are valid SonicWall zones
- **Group Creation**: Automatically creates address groups when multiple objects are specified

### Supported Address Types
- **Host Addresses**: Single IP addresses (192.168.1.1)
- **Network Addresses**: Network ranges with subnet masks
- **FQDN Objects**: Domain names (example.com)

### Supported Zones
- WAN
- LAN
- MDT
- CLIENT LAN
- SYSINT
- SYSEXT
- SYSCLIENT
- DMZ

## Installation

### Prerequisites
- Windows, macOS, or Linux
- Python 3.7 or higher
- Tkinter (usually included with Python)

### Installation Steps
1. **Download or Clone the Repository**
   ```bash
   git clone https://github.com/Crispy-Pasta/SonicwallCLIConverter.git
   cd SonicwallCLIConverter
   ```

2. **Run the Application**
   ```bash
   python CLIConverterUI.py
   ```

## User Interface Overview

### Main Window Components

1. **Global Fields (Top Section)**
   - **SR Number**: Service request number (applies to all entries)
   - **Group Name**: Name for address group creation (optional)

2. **Entry Fields (Middle Section)**
   - **Name**: Object name for the address object
   - **IPAddress**: IP address or FQDN
   - **Subnet**: Subnet mask (dotted decimal or CIDR notation)
   - **Zone**: Security zone dropdown
   - **Action**: Remove button for each entry

3. **Control Buttons**
   - **Add Entry**: Creates a new input row
   - **Upload TXT File**: Imports data from a text file
   - **Convert to CLI**: Generates SonicWall CLI commands
   - **Save CLI Output**: Saves generated commands to a file

4. **Output Area (Bottom Section)**
   - Displays generated CLI commands
   - Read-only text area for review before saving

## Usage Instructions

### Method 1: Manual Entry

1. **Launch the Application**
   ```bash
   python CLIConverterUI.py
   ```

2. **Fill Global Fields (Optional)**
   - Enter SR Number if required
   - Enter Group Name if creating an address group

3. **Enter Address Object Data**
   - **Name**: Enter a descriptive name for the object
   - **IPAddress**: Enter IP address or FQDN
   - **Subnet**: Enter subnet mask (e.g., 255.255.255.0 or /24)
   - **Zone**: Select appropriate zone from dropdown

4. **Add More Entries** (if needed)
   - Click "Add Entry" to create additional rows
   - Fill in the required information

5. **Generate CLI Commands**
   - Click "Convert to CLI" to generate commands
   - Review the output in the text area

6. **Save Output**
   - Click "Save CLI Output" to save commands to a file
   - Choose location and filename

### Method 2: File Upload

1. **Prepare Your TXT File**
   Format should follow this pattern:
   ```
   ZONE Object Name
   IP/CIDR
   ZONE
   ```

   Example:
   ```
   WAN Server001
   192.168.1.100/24
   WAN
   
   LAN Workstation-Range
   10.0.1.0/24
   LAN
   ```

2. **Upload the File**
   - Click "Upload TXT File"
   - Select your prepared TXT file
   - Data will automatically populate the entry fields

3. **Review and Convert**
   - Review the populated data
   - Make any necessary adjustments
   - Click "Convert to CLI" to generate commands

## Input Formats

### IP Address Formats
- **Single IP**: `192.168.1.100`
- **FQDN**: `server.example.com`

### Subnet Mask Formats
- **Dotted Decimal**: `255.255.255.0`
- **CIDR Notation**: `/24`

### TXT File Format
The application expects a specific format for TXT files:

```
[ZONE] [Object Name]
[IP Address]/[CIDR or Subnet]
[Zone]
[Optional: Number]
[Optional: IPv4]
```

#### Example TXT File Content:
```
WAN WebServer001
192.168.1.100/24
WAN
1
IPv4

LAN Database-Server
10.0.1.50
LAN

DMZ Email-Gateway
mail.company.com
DMZ
```

## Generated CLI Commands

### Sample Output
```
configure
address-object ipv4 "WebServer001" network 192.168.1.100 255.255.255.0 zone WAN
address-object ipv4 "Database-Server" host 10.0.1.50 zone LAN
address-object fqdn "Email-Gateway" domain mail.company.com zone DMZ
commit
address-group ipv4 "GroupName SR12345"
address-object ipv4 "WebServer001"
address-object ipv4 "Database-Server"
address-object ipv4 "Email-Gateway"
exit
commit
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Application Won't Start
**Problem**: Python or Tkinter not properly installed
**Solution**: 
- Ensure Python 3.7+ is installed
- Verify Tkinter is available: `python -c "import tkinter"`

#### 2. Invalid IP/FQDN Format Error
**Problem**: Input doesn't match expected format
**Solution**:
- Verify IP addresses are in correct format (192.168.1.1)
- Ensure FQDNs are valid (example.com)
- Check for extra spaces or characters

#### 3. Invalid Subnet Mask Error
**Problem**: Subnet mask format not recognized
**Solution**:
- Use dotted decimal (255.255.255.0) or CIDR (/24)
- Ensure CIDR values are between /0 and /32

#### 4. Zone Validation Error
**Problem**: Invalid zone selected
**Solution**:
- Use only supported zones: WAN, LAN, MDT, CLIENT LAN, SYSINT, SYSEXT, SYSCLIENT, DMZ
- Check for correct spelling and capitalization

#### 5. TXT File Not Parsing Correctly
**Problem**: File format not recognized
**Solution**:
- Follow exact format specified in manual
- Ensure proper line breaks between entries
- Remove any extra blank lines or characters

### Log Files

The application creates detailed log files in the `logs/` directory:
- **Location**: `logs/sonicwall_cli_converter_YYYYMMDD.log`
- **Content**: Detailed operation logs, errors, and debug information

### Debugging Tips

1. **Check Log Files**: Always review log files for detailed error information
2. **Validate Input Data**: Ensure all input follows specified formats
3. **Test with Simple Data**: Start with basic entries to isolate issues
4. **Clear Data**: Use "Remove" buttons to clear problematic entries

## FAQ

### Q: Can I use the application without an internet connection?
**A**: Yes, the application runs completely offline and doesn't require internet connectivity.

### Q: What Python versions are supported?
**A**: Python 3.7 or higher is required. The application has been tested with Python 3.8, 3.9, and 3.10.

### Q: Can I process multiple TXT files at once?
**A**: Currently, the application processes one file at a time. You can upload multiple files sequentially.

### Q: Are there any limits on the number of entries?
**A**: There are no hard limits, but performance may be affected with very large datasets (1000+ entries).

### Q: Can I customize the supported zones?
**A**: The supported zones are hardcoded for SonicWall compatibility. Contact the developer for custom zone requirements.

### Q: How do I create address groups?
**A**: Enter a Group Name in the global fields. If you have multiple entries, the application will automatically create an address group containing all objects.

### Q: What if I need to modify the generated CLI commands?
**A**: The output text area allows you to view and copy commands. You can paste them into a text editor for manual modifications before applying to your firewall.

### Q: Is there a way to validate the generated commands before applying them?
**A**: The application validates input formats, but you should always review generated commands and test them in a lab environment before production deployment.

---

**For additional support, please check the project repository or create an issue on GitHub.**
