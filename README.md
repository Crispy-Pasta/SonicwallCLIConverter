# SonicWall CLI Converter UI

## Overview

The SonicWall CLI Converter UI is a graphical application designed to convert network address and service objects from structured input into SonicWall CLI commands. The application supports:

- IPs
- Subnets
- Zones
- Optional group names for address objects

## Features

- **Multiple Input Formats**: Supports manual entry or uploading a structured TXT file to auto-fill entries.
- **Input Validation**: Validates IP addresses, subnet masks, and FQDN formats.
- **CLI Generation**: Converts entered/loaded data into SonicWall CLI commands.
- **Add/Remove Entries**: Dynamically add and remove entry rows with buttons for each row.
- **Logging**: Comprehensive logging for troubleshooting.

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Crispy-Pasta/SonicwallCLIConverter.git
   cd SonicwallCLIConverter
   ```

2. **Run the Application**
   - Ensure you have Python 3.x installed.
   - Run the following command:
   ```bash
   python CLIConverterUI.py
   ```

## Project Structure

- `CLIConverterUI.py`: Main application code.
- `logs/`: Directory for log files.

## Requirements

- Python 3.x
- Tkinter

## License

This project is licensed under the MIT License.
