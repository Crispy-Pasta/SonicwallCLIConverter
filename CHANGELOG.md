# Changelog

All notable changes to the SonicWall CLI Converter UI project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-01-05

### Added
- **Comprehensive Logging System**: Added detailed logging for troubleshooting and debugging
- **CIDR Notation Support**: Now supports both CIDR notation (/24) and dotted decimal subnet masks
- **Improved FQDN Detection**: Enhanced detection and handling of fully qualified domain names
- **Enhanced UI Layout**: Unified header and entry widget layout for perfect field alignment
- **Version Information**: Added application version, author, and last updated metadata
- **Documentation Suite**:
  - Comprehensive README.md
  - Detailed USER_MANUAL.md with troubleshooting guide
  - UML workflow diagram
  - Sample input file for testing
  - Requirements.txt and .gitignore files

### Changed
- **UI Architecture**: Restructured UI to use unified grid layout for better alignment
- **Entry Management**: Improved dynamic entry creation and removal system
- **Error Handling**: Enhanced error messages and validation feedback
- **Code Organization**: Added proper method documentation and inline comments

### Fixed
- **Field Alignment Issues**: Resolved misalignment between headers and input fields
- **CIDR Conversion**: Fixed conversion from CIDR notation to dotted decimal format
- **FQDN Processing**: Improved parsing of domain names from TXT files
- **Widget Cleanup**: Enhanced entry removal to properly clean up all related widgets

### Technical Improvements
- Added logging to key methods for easier debugging
- Implemented CIDR to subnet mask conversion utility
- Enhanced FQDN detection with regex validation
- Improved file parsing for mixed IP and FQDN entries
- Added comprehensive error logging and validation

## [1.0.0] - Previous Version

### Initial Features
- Basic GUI interface for SonicWall CLI generation
- Manual entry of address objects
- TXT file upload functionality
- Zone selection dropdown
- CLI command generation
- Basic validation for IP addresses and zones

---

## Version History Summary

- **v2.0.0**: Major update with logging, CIDR support, improved UI, and comprehensive documentation
- **v1.0.0**: Initial release with basic functionality
