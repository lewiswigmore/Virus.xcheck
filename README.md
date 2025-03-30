```
██╗   ██╗██╗██████╗ ██╗   ██╗███████╗   ██╗  ██╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
██║   ██║██║██╔══██╗██║   ██║██╔════╝   ╚██╗██╔╝██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
██║   ██║██║██████╔╝██║   ██║███████╗    ╚███╔╝ ██║     ███████║█████╗  ██║     █████╔╝ 
╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║    ██╔██╗ ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
 ╚████╔╝ ██║██║  ██║╚██████╔╝███████║██╗██╔╝ ██╗╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
```
<p align="left">
      <a href="https://github.com/0xlews"><img src="https://img.shields.io/badge/GitHub-Follow%20on%20GitHub-inactive.svg?logo=github"></a>
      <a href="https://twitter.com/0xlews"><img src="https://img.shields.io/badge/Twitter-Follow%20on%20Twitter-informational.svg?logo=x"></a>
</p>
 
## Overview
Virus.xcheck is a Python tool designed to check the existence of file hashes in the Virus Exchange database. Due to the storage method used by Virus Exchange, only SHA-256 hashes are supported. However, for other hash types, the tool will return a VirusTotal URL. The tool can read SHA-256 hashes from a CSV file or accept a single hash from the command line, verifying each one against the Virus Exchange database.

## Features
- Reads hashes from a CSV file or a single hash from the command line
- Checks each hash against the Virus Exchange API with S3 bucket fallback
- Parallel processing for efficient handling of larger files
- Colorized, beautifully formatted output in the terminal
- Outputs the results in JSON or CSV format
- Command-line interface with multiple options
- API key management with .env file support
- Rate limiting to prevent API throttling

## Requirements
- Python 3.6+

## Installation

### Using pip
Install the required packages using the provided requirements.txt file:

```bash
pip install -r requirements.txt
```

### API Key Setup
1. Get an API key from [Virus.Exchange](https://virus.exchange/)
2. Create a `.env` file in the root directory with your API key:
   ```
   VIRUSXCHECK_API_KEY=your_api_key_here
   ```
   Alternatively, you can provide the API key via command line:
   ```bash
   python virusxcheck.py -s "hash_value" -k "your_api_key_here" --save-config
   ```
   The `--save-config` option will save the API key to the .env file for future use.

## Usage
Execute the script from the command line with the following options:

### Check a single hash
```bash
python virusxcheck.py -s "hash_value"
```

### Process multiple hashes from a CSV file
```bash
python virusxcheck.py -f /path/to/your/hashes.csv
```

### Save results to a file
```bash
python virusxcheck.py -f /path/to/hashes.csv -o /path/to/results.csv
python virusxcheck.py -s "hash_value" -o /path/to/results.json
```

### Disable colored output
```bash
python virusxcheck.py -s "hash_value" --no-color
```

## Command-Line Arguments
- `-s, --single`: Single hash string to check
- `-f, --file`: Path to CSV file containing hashes
- `-o, --output`: Path to output file (CSV or JSON format)
- `-k, --apikey`: Virus.Exchange API key
- `--save-config`: Save API key to .env file
- `--no-color`: Disable colored output

## Output Formats

### Terminal Output
The tool produces beautifully formatted and colored output in the terminal:
- Red for malicious files found in the database
- Green for clean files not found
- Yellow for warnings and errors
- Comprehensive metadata display with file information, names, tags, and links

### JSON Output
```json
{
    "dbd5e933fe023ee03953ed8a8997c58be05ba97c092b795647962cf111bcd540": {
        "status": "Found in VX database",
        "details": {
            "md5": "d51c19925a2ae853d3b19a1259f86de5",
            "size": 4042752,
            "type": "unknown",
            "names": [
                "csrss.exe",
                "app.exe"
            ],
            "sha1": "332a18521f2905e233bbab094a021cee44ac750e",
            "tags": [
                "spreader",
                "peexe",
                "executable",
                "windows"
            ],
            "first_seen": "2025-03-30T17:36:55Z",
            "download_link": "https://s3.us-east-1.wasabisys.com/vxugmwdb/dbd5e933fe023ee03953ed8a8997c58be05ba97c092b795647962cf111bcd540"
        },
        "virustotal_url": "https://www.virustotal.com/gui/file/dbd5e933fe023ee03953ed8a8997c58be05ba97c092b795647962cf111bcd540"
    }
}
```

### CSV Output
The CSV output includes columns for:
- Hash
- VX Status
- File Type
- Size
- First Seen
- Names
- VX URL
- Download Link
- VirusTotal URL

## Disclaimer
This tool is for informational purposes only. Ensure you have the right to access and check the hashes against the database and always comply with the terms of service of the Virus Exchange API.
