```
██╗   ██╗██╗██████╗ ██╗   ██╗███████╗   ██╗  ██╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
██║   ██║██║██╔══██╗██║   ██║██╔════╝   ╚██╗██╔╝██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
██║   ██║██║██████╔╝██║   ██║███████╗    ╚███╔╝ ██║     ███████║█████╗  ██║     █████╔╝ 
╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║    ██╔██╗ ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
 ╚████╔╝ ██║██║  ██║╚██████╔╝███████║██╗██╔╝ ██╗╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
```
<p align="left">
      <a href="https://github.com/lewiswigmore"><img src="https://img.shields.io/badge/GitHub-Follow%20on%20GitHub-inactive.svg?logo=github"></a>
      <a href="https://twitter.com/lewiswigmore"><img src="https://img.shields.io/badge/Twitter-Follow%20on%20Twitter-informational.svg?logo=x"></a>
</p>
 
## Overview
Virus.xcheck is a Python tool designed to check the existence of file hashes in the Virus Exchange database. Due to the storage method used by Virus Exchange, only SHA-256 hashes are supported. However, for other hash types, the tool will return VirusTotal data. The tool can read SHA-256 hashes from a CSV file or accept a single hash from the command line, verifying each one against the Virus Exchange database.

## Features
- Reads hashes from a CSV file or a single hash from the command line
- Checks each hash against the Virus Exchange API with S3 bucket fallback
- Parallel processing for efficient handling of larger files
- Colorised and formatted output in the terminal
- Outputs the results in JSON or CSV format
- Rate limiting to prevent API throttling
- Interactive HTML reports with visualisations

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

### Generate HTML report
```bash
python virusxcheck.py -f /path/to/hashes.csv --html report.html
```

### Disable colored output
```bash
python virusxcheck.py -s "hash_value" --no-color
```

## Test Examples

### Sample Hashes for Testing
```
d00853e592bccd823027e7e685d88c5a1f76a5a36ec5b7073d49ee633b050cc8
3965811a37eded16030a1dd4ac57119ce774bed4fcd70a232011f8f86efbfd83
51919bdfd8bc0ebeec651efdd5d97dae7ad9532cb10f6efaa67c3dbc88ea7500
```

### Testing with Sample CSV
Create a file `test_hashes.csv` with the above hashes and run:
```bash
python virusxcheck.py -f test_hashes.csv --html results/report.html -o results/output.csv
```

### Sample Output
When running the tool with the test hashes, you'll see output similar to:
```
VirusTotal API integration enabled
Processing: 100%|██████████████████████| 3/3 [00:00<00:00, 5.85it/s]
HTML report saved to results/report.html
Results saved to results/output.csv
```

The terminal will display detailed information about each hash, including:
- Detection status (found/not found)
- File metadata (size, type, first seen)
- Known filenames
- Tags associated with the sample
- VirusTotal detection statistics
- Download and reference links

## Command-Line Arguments
- `-s, --single`: Single hash string to check
- `-f, --file`: Path to CSV file containing hashes
- `-o, --output`: Path to output file (CSV or JSON format)
- `-k, --apikey`: Virus.Exchange API key
- `--vt-apikey`: VirusTotal API key
- `--html`: Generate HTML report with interactive charts
- `--save-config`: Save API keys to .env file
- `--no-color`: Disable colored output

## Output Formats

### Terminal Output
The tool produces a colored output in the terminal:
- Red for malicious files found in the database
- Green for clean files not found
- Yellow for warnings and errors
- Metadata display with file information, names, tags, and links

### HTML Reports
The HTML reports include:
- Interactive charts showing detection rates and statistics
- File metadata and statistics
- Malware tag classification
- Detailed scan results from VirusTotal

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
- VT Detection Rate
- VT Malicious
- VT Suspicious
- VT Clean
- VT Type
- VT First Seen
- VT Tags

## Disclaimer
This tool is for informational purposes only. Ensure you have the right to access and check the hashes against the database and always comply with the terms of service of the Virus Exchange and VirusTotal APIs.
