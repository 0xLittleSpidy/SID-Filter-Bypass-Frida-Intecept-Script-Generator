# SID Filter Bypass Frida Intercept Script Generator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)

A Python-based tool for generating Frida interception scripts to bypass SID filtering (CVE-2020-0665).

**Special Thanks** to [Dirk-jan Mollema (@_dirkjan)](https://twitter.com/_dirkjan) for the original [frida_intercept.py](https://github.com/dirkjanm/forest-trust-tools/blob/master/frida_intercept.py) script and his groundbreaking work on Active Directory security research.

## Features

- 🛠️ **Automatic SID Conversion**
  - Converts SIDs to little-endian hexadecimal format
  - Handles dynamic SID prefixes (S-R-I-S-...)
  - Validates SID structure and components

- 📁 **Smart Output Handling**
  - Generates ready-to-use Frida scripts
  - Custom output file naming
  - Debug mode for conversion details

## Installation

**Clone the repository**
   ```bash
   git clone https://github.com/0xLittleSpidy/SID-Filter-Bypass-Frida-Intercept-Script-Generator.git
   cd SID-Filter-Bypass-Frida-Script-Generator
   ```

## Usage

### Basic Command
```bash
python frida_intercept_script_generator.py \
  -c "S-1-5-21-2327345182-1863223493-3435513819" \
  -f "S-1-5-21-1234567890-0987654321-1122334455"
```

### Full Options
```bash
python sid_bypass.py \
  --child-sid "S-1-5-21-..." \
  --forest-sid "S-1-5-21-..." \
  --output custom_intercept.py \
  --debug
```

| Option | Description |
|--------|-------------|
| `-c`, `--child-sid` | Child domain SID (required) |
| `-f`, `--forest-sid` | Forest server local SID (required) |
| `-o`, `--output` | Output filename (default: frida_intercept.py) |
| `-d`, `--debug` | Enable debug output |

## How It Works

### Conversion Process
1. **SID Parsing**
   ```text
   Input SID: S-1-5-21-3623811015-3361044348-30300820-1013
   ├── Prefix: S-1-5-21-
   └── Components: 3623811015, 3361044348, 30300820, 1013
   ```

2. **Hexadecimal Conversion**
   ```text
   3623811015 → 0xAC, 0x4A, 0x14, 0xAF
   3361044348 → 0xC2, 0xC6, 0xCE, 0x09
   ```

3. **Script Generation**
   ```javascript
   var buf1 = [0x01, 0x04, 0x00, 0x00, ..., 0xAC, 0x4A, 0x14, 0xAF];
   var newsid = [0x01, 0x04, 0x00, 0x00, ..., 0xC2, 0xC6, 0xCE, 0x09];
   ```


## Contributing
Contributions are welcome! If you'd like to contribute to this project, please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes.
4. Submit a pull request.

---

# **Ethical Use Only**  

This tool is intended for **legal and authorized security assessments only**. By using this software, you agree to comply with all applicable laws and regulations.  

## **Legal Disclaimer**  
The developers of this tool are **not responsible** for any misuse or illegal activities conducted with it.

---  
*By using this tool, you acknowledge that you understand and agree to these terms.*
