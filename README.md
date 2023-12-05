# Virus.xcheck

## Overview
Virus.xcheck is a Python tool designed to verify the existence of file hashes in the Virus Exchange database. It reads a list of hashes from a CSV file and checks each hash against a specified URL. If a file corresponding to the hash exists, the URL is returned; otherwise, it's indicated that the file was not found.

## Features
- Reads hashes from a CSV file.
- Checks each hash against Virus.exchange server.
- Supports large sets of hashes.
- Outputs the results in JSON format.

## Requirements
- Python 3
- `requests` library

## Installation
Before running the script, ensure you have Python 3 installed on your system. You also need to install the `requests` library, which can be done using pip:

```bash
pip install requests
```

## Usage
To use Virus.xcheck, you need to have a CSV file containing the hashes to check. The script is executed from the command line with the following format:

```bash
python virusxcheck.py -f /path/to/your/hashes.csv
```

### Arguments
- `-f` or `--file`: Path to the CSV file containing hashes.

## Output
The tool outputs the results in JSON format, where each hash is mapped to its status ('Found' or 'Not Found') and the corresponding URL if found.

Example output:

```json
{
    "199bb829d3280509e9842e3af9c024e625eebca19a4cb44603a3c25ee1ccfd42": {
        "url": "https://s3.us-east-1.wasabisys.com/vxugmwdb/199bb829d3280509e9842e3af9c024e625eebca19a4cb44603a3c25ee1ccfd42",
        "status": "Found"
    },
    "anotherhashvalue": {
        "status": "Not Found"
    }
}
```

## Disclaimer
This tool is for informational purposes only. Ensure you have the right to access and check the hashes against the database and always comply with the terms of service of the website.