```
██╗   ██╗██╗██████╗ ██╗   ██╗███████╗   ██╗  ██╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
██║   ██║██║██╔══██╗██║   ██║██╔════╝   ╚██╗██╔╝██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
██║   ██║██║██████╔╝██║   ██║███████╗    ╚███╔╝ ██║     ███████║█████╗  ██║     █████╔╝ 
╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║    ██╔██╗ ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
 ╚████╔╝ ██║██║  ██║╚██████╔╝███████║██╗██╔╝ ██╗╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
```

## Overview
Virus.xcheck is a Python tool that verifies the existence of file hashes in the Virus Exchange database. It supports MD5, SHA1, SHA256, and SHA512 hashes. The tool can read hashes from a CSV file or a single hash from the command line, checking each against the Virus Exchange database.

## Features
- Reads hashes from a CSV file or a single hash from the command line.
- Checks each hash against the Virus Exchange database.
- Supports MD5, SHA1, SHA256, and SHA512 hashes.
- Parallel processing for efficient handling of larger files.
- Outputs the results in JSON or CSV format.
- Command-line interface with multiple usage options.
- Checks are rate limited to 15 requests per second.

## Requirements
- Python 3
- Libraries: `requests`, `tqdm`, `ratelimit`

## Installation
Ensure Python 3 is installed on your system. Install the required libraries using pip:

```bash
pip install requests tqdm ratelimit
```

## Usage
Getting started and usage guide:

```bash
python virusxcheck.py
```

Execute the script from the command line with the following format:

```bash
python virusxcheck.py -f /path/to/your/hashes.csv
```

To save the output in a custom-named CSV file:

```bash
python virusxcheck.py -f /path/to/hashes.csv -o /path/to/custom_output.csv
```

To check a single hash:

```bash
python virusxcheck.py -s "hash_value"
```

### Arguments
- `-f` or `--file`: Path to the CSV file containing hashes.
- `-o` or `--output`: Path to the output file (CSV or JSON format).
- `-s` or `--single`: Single hash string to check.

### Output
The tool outputs the results in either JSON or CSV format, where each hash is mapped to its status ('Found' or 'Not Found') and the corresponding download URL if found.

You can specify the output format (JSON or CSV) using the -o option followed by the desired file extension:
- JSON: `-o output.json`
- CSV: `-o output.csv`

Example output (JSON):

```json
{
    "199ab829c3280509d9842e31f9g024h6254i2jk19l4mn44603o3p25qe1s74t42": {
        "url": "https://s3.us-east-1.wasabisys.com/vxugmwdb/199ab829c3280509d9842e31f9g024h6254i2jk19l4mn44603o3p25qe1s74t42",
        "status": "Found"
    },
    "anotherhashvalue": {
        "status": "Not Found"
    }
}
```

## Disclaimer
This tool is for informational purposes only. Ensure you have the right to access and check the hashes against the database and always comply with the terms of service of the website.