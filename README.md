# SonicWall CLI Converter v2.2

## Overview

The SonicWall CLI Converter UI is a graphical application that facilitates the conversion of network address and service objects into SonicWall CLI commands. It automates the process of transforming structured input into correctly formatted CLI instructions for SonicWall devices.

## Key Features

- **Mixed Format Support**: Handles both manual entry and structured TXT file uploads with complex formats.
- **Validation and Parsing**: Validates IPs, subnets, FQDNs, zones, and protocols with robust parsing logic.
- **Command Generation**: Produces SonicWall CLI commands suitable for network configurations.
- **Dynamic Entry Management**: Allows dynamic addition/removal of entry rows with inline editing.
- **Pagination Support**: Efficiently handles large files with 50+ entries using 10 entries per page.
- **Comprehensive Logging**: Provides detailed logs for troubleshooting and debugging.

## Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/Crispy-Pasta/SonicwallCLIConverter.git
   cd SonicwallCLIConverter
   ```

2. **Run the Application**
   - Ensure Python 3.x is installed.
   - Execute the application:
   ```bash
   python CLIConverterUI.py
   ```

## Requirements

- Python 3.x
- Tkinter (packaged with most Python installations)

## Directory Structure

- `CLIConverterUI.py`: Main application script.
- `logs/`: Directory containing log files for each session.

## Licensing

This project is licensed under the MIT License.

## Version History

- **v2.2 (2025-08-05)**: Added pagination support for handling large numbers of entries (10 per page), improved GUI scalability.
- **v2.1 (2025-08-05)**: Enhanced parsing for mixed formats, added NOC zone, improved logging.
- **v2.0**: Introduced service object handling, tabbed UI, and enhanced validation.
- **v1.0**: Initial release with address object handling.

## Troubleshooting

- **Log Access**: Check the `logs/` directory for error and processing logs.
- **Common Issues**:
  - Incorrect file format: Ensure files are correctly structured according to the latest documentation.
  - Invalid zones/protocols: Verify that all input values are within supported ranges.

## Contributions

Contributions are welcome. Please submit a pull request or report issues via the repository's issue tracker.

## Acknowledgments

- SonicWall community for documentation and support.
- Contributors who provided feedback and testing.
- GUI development with Python's Tkinter library.


## Supported File Formats

### Address Objects
```
IPv4
Server_Name
192.168.1.10/255.255.255.255
LAN
2
```

### Service Objects
```
HTTP_Service
TCP
80
80
```

## Supported Zones
WAN, LAN, DMZ, MDT, CLIENT LAN, SYSINT, SYSEXT, SYSCLIENT, NOC

## Supported Protocols
TCP, UDP, ICMP, IGMP, GRE, ESP, AH, ICMPv6, EIGRP, OSPF, PIM, L2TP, 6over4
