# SonicWall CLI Converter - Troubleshooting Guide

## Overview

This document provides comprehensive troubleshooting information for the SonicWall CLI Converter v2.1. Use this guide to resolve common issues and understand error messages.

## Quick Diagnostics

### Check Log Files
1. Navigate to the `logs/` directory in your application folder
2. Open the latest log file: `sonicwall_cli_converter_YYYYMMDD.log`
3. Look for ERROR or WARNING messages related to your issue

### Common Error Patterns
- **IndexError**: File format issues
- **KeyError**: Missing data fields
- **ValidationError**: Invalid input data
- **FileNotFoundError**: Missing or inaccessible files

## Address Object Issues

### Error: "Failed to load file: list index out of range"

**Symptoms:**
- Application crashes when uploading address object files
- Log shows IndexError messages

**Causes:**
1. Incorrect file format
2. Incomplete entries (missing lines)
3. Mixed format not properly structured

**Solutions:**
1. **Check File Format**: Ensure your file follows the 5-line format:
   ```
   IPv4
   Object_Name
   192.168.1.10/255.255.255.255
   LAN
   2
   ```

2. **Verify Complete Entries**: Each address object needs all 5 lines
3. **Check File Encoding**: Save file as UTF-8 encoding
4. **Remove Empty Lines**: Ensure no blank lines between entries

**Example Fix:**
```
# Bad format (will cause errors):
IPv4
Server1
192.168.1.10
# Missing subnet and zone lines

# Good format:
IPv4
Server1
192.168.1.10/255.255.255.255
LAN
2
```

### Error: "Zone 'X' not in allowed list"

**Symptoms:**
- Entries are skipped during file upload
- Warning messages in logs about zones

**Allowed Zones:**
- WAN, LAN, DMZ, MDT, CLIENT LAN, SYSINT, SYSEXT, SYSCLIENT, NOC

**Solutions:**
1. **Use Supported Zones**: Replace unsupported zones with valid ones
2. **Add Custom Zone**: Modify `allowed_zones` in `CLIConverterUI.py`:
   ```python
   self.allowed_zones = {"WAN", "LAN", "DMZ", "CUSTOM_ZONE"}
   ```

### Error: "Invalid IP format"

**Symptoms:**
- Validation error when converting to CLI
- Specific entry fails validation

**Supported Formats:**
- Host IP: `192.168.1.10`
- CIDR: `192.168.1.0/24`
- IP with mask: `192.168.1.10` + `255.255.255.0`
- FQDN: `server.example.com`

**Solutions:**
1. **Check IP Syntax**: Ensure valid IPv4 format
2. **Verify CIDR**: Use correct CIDR notation (/1 to /32)
3. **Test FQDN**: Ensure domain names are properly formatted

## Service Object Issues

### Error: "Protocol 'X' not in allowed list"

**Symptoms:**
- Service entries are skipped
- Protocol validation fails

**Allowed Protocols:**
- TCP, UDP, ICMP, IGMP, GRE, ESP, AH, ICMPv6, EIGRP, OSPF, PIM, L2TP, 6over4

**Solutions:**
1. **Use Standard Protocols**: Check protocol spelling and case
2. **Add Custom Protocol**: Modify `allowed_protocols` in code
3. **Check File Content**: Verify protocol names in input file

### Error: "Invalid port range"

**Symptoms:**
- Port validation fails
- Error message about port numbers

**Valid Port Rules:**
- Range: 1-65535
- Start port ≤ End port
- Numeric values only

**Solutions:**
1. **Check Port Numbers**: Ensure ports are within valid range
2. **Verify Range**: Start port must be ≤ end port
3. **Remove Non-numeric**: Ensure no letters or special characters

## File Format Issues

### Mixed Format Parsing Problems

**Symptoms:**
- Only some entries load from file
- Inconsistent parsing results

**Expected Format (Address Objects):**
```
IPv4
Object_Name_1
192.168.1.10/255.255.255.255
LAN
2
IPv4
Object_Name_2
10.0.0.0/255.255.0.0
WAN
3
```

**Solutions:**
1. **Consistent Format**: Ensure all entries follow the same pattern
2. **Check Separators**: Verify numeric separators are present
3. **No Mixed Formats**: Don't combine different file formats

### Line Number Issues

**Symptoms:**
- Parsing errors with numbered lines
- Content appears incorrect

**If File Has Line Numbers:**
```
1|IPv4
2|Server_Name
3|192.168.1.10/255.255.255.255
4|LAN
5|2
```

**Solutions:**
1. **Automatic Removal**: Application should automatically remove line numbers
2. **Manual Cleanup**: Remove line numbers if automatic removal fails
3. **Check Format**: Ensure line numbers follow "number|content" format

## Application Issues

### Application Won't Start

**Symptoms:**
- Python error on startup
- Import errors
- GUI doesn't appear

**Solutions:**
1. **Check Python Version**: Requires Python 3.7+
2. **Verify Tkinter**: Ensure tkinter is installed
3. **Check Dependencies**: No external dependencies required
4. **Run from Command Line**: See specific error messages

**Command Line Test:**
```bash
python CLIConverterUI.py
```

### Memory Issues with Large Files

**Symptoms:**
- Application becomes slow
- Out of memory errors
- Crashes with large files

**Recommendations:**
- Maximum file size: 5MB
- Maximum entries: 1000 objects
- Process large files in smaller batches

**Solutions:**
1. **Split Large Files**: Divide into smaller files
2. **Process in Batches**: Upload files in groups
3. **Clear Entries**: Remove entries before loading new files

## CLI Generation Issues

### Invalid Command Output

**Symptoms:**
- Generated commands don't work on SonicWall
- Syntax errors in CLI output

**Common Issues:**
1. **Special Characters**: Object names with quotes or spaces
2. **Reserved Words**: Using SonicWall reserved keywords
3. **Long Names**: Names exceeding character limits

**Solutions:**
1. **Clean Names**: Remove special characters from object names
2. **Check Length**: Keep names under 64 characters
3. **Test Commands**: Validate on SonicWall test environment

### Group Creation Errors

**Symptoms:**
- Groups not created properly
- Objects not added to groups

**Requirements:**
- All objects must be in the same zone for group creation
- Group names cannot contain special characters

**Solutions:**
1. **Zone Consistency**: Ensure all objects use the same zone
2. **Name Validation**: Use alphanumeric characters only
3. **Manual Verification**: Check group creation on SonicWall

## Performance Optimization

### Slow File Processing

**Causes:**
- Large files
- Complex parsing logic
- Excessive logging

**Solutions:**
1. **Reduce File Size**: Process smaller files
2. **Disable Debug Logging**: Change log level to INFO
3. **Close Other Applications**: Free up system resources

### Memory Usage

**Monitoring:**
- Watch Task Manager during processing
- Monitor log file sizes
- Check available disk space

**Optimization:**
1. **Regular Cleanup**: Delete old log files
2. **Restart Application**: For very large processing jobs
3. **System Resources**: Ensure adequate RAM available

## Advanced Troubleshooting

### Debug Mode

**Enable Detailed Logging:**
1. Open `CLIConverterUI.py`
2. Find the logging configuration
3. Change level to `DEBUG` if not already set

**Log Analysis:**
- Look for specific function names in errors
- Check line numbers for exact error locations
- Trace the processing flow through debug messages

### Custom Modifications

**Adding New Zones:**
```python
# In CLIConverterUI.py, modify:
self.allowed_zones = {"WAN", "LAN", "DMZ", "YOUR_ZONE"}
```

**Adding New Protocols:**
```python
# In CLIConverterUI.py, modify:
self.allowed_protocols = {"TCP", "UDP", "YOUR_PROTOCOL"}
```

### File Encoding Issues

**Symptoms:**
- Strange characters in parsed data
- Encoding errors in logs

**Solutions:**
1. **Save as UTF-8**: Ensure input files use UTF-8 encoding
2. **Check BOM**: Remove Byte Order Mark if present
3. **Text Editor**: Use editors that properly handle encoding

## Getting Help

### Information to Provide

When reporting issues, include:
1. **Error Message**: Exact error text
2. **Log File**: Relevant log file sections
3. **Sample Data**: Example input file (sanitized)
4. **System Info**: Python version, OS
5. **Steps to Reproduce**: Detailed steps that cause the issue

### Common Solutions Summary

| Issue | Quick Fix |
|-------|-----------|
| Index out of range | Check file format (5-line structure) |
| Zone not allowed | Use supported zones or modify code |
| Protocol not allowed | Use supported protocols |
| Invalid IP format | Check IP syntax and format |
| Invalid port range | Ensure ports are 1-65535 |
| File encoding error | Save file as UTF-8 |
| Memory issues | Process smaller files |
| Slow performance | Reduce file size, check system resources |

### Prevention Tips

1. **Validate Input**: Always check file format before upload
2. **Test Small Files**: Start with small test files
3. **Regular Backups**: Keep copies of working configurations
4. **Monitor Logs**: Check logs regularly for warnings
5. **Update Regularly**: Use the latest version of the application

This troubleshooting guide should help resolve most common issues. For additional support, check the application logs and consider reaching out through the project's GitHub issues page.
