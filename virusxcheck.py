"""

██╗   ██╗██╗██████╗ ██╗   ██╗███████╗   ██╗  ██╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
██║   ██║██║██╔══██╗██║   ██║██╔════╝   ╚██╗██╔╝██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
██║   ██║██║██████╔╝██║   ██║███████╗    ╚███╔╝ ██║     ███████║█████╗  ██║     █████╔╝ 
╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║    ██╔██╗ ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
 ╚████╔╝ ██║██║  ██║╚██████╔╝███████║██╗██╔╝ ██╗╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
                                                                                        
"""

import sys
import csv
import requests
import argparse
import json
import re
import concurrent.futures
from tqdm import tqdm

def read_csv(file_path):
    hashes = []
    hex_pattern = re.compile(r'\b[a-fA-F0-9]{32,128}\b')  # Regex pattern for MD5, SHA1, SHA256, SHA512
    try:
        with open(file_path, mode='r', newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            for row in reader:
                for value in row:
                    match = hex_pattern.search(value)
                    if match:
                        hashes.append(match.group())
        return hashes
    except FileNotFoundError:
        print(f"Error: File not found - {file_path}")
        exit(1)
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        exit(1)

def check_hash(hash_value, session):
    if len(hash_value) not in [32, 40, 64, 128]:
        return "Unsupported hash length"
    url = f"https://s3.us-east-1.wasabisys.com/vxugmwdb/{hash_value}"
    try:
        response = session.head(url)
        if response.status_code == 200:
            return url
        elif response.status_code == 404:
            return "Not Found"
        else:
            return f"Error: HTTP {response.status_code}"
    except requests.RequestException as e:
        return f"Request Error: {e}"

def write_to_csv(file_path, data):
    with open(file_path, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Hash', 'URL', 'Status'])
        for hash_value, details in data.items():
            writer.writerow([hash_value, details.get('url', ''), details['status']])

def write_to_json(file_path, data):
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def main():
    parser = argparse.ArgumentParser(description='Virus.xcheck CLI Tool')
    parser.add_argument('-f', '--file', help='Path to CSV file containing hashes')
    parser.add_argument('-o', '--output', help='Path to output file (CSV or JSON format)')
    parser.add_argument('-s', '--single', help='Single hash string to check')
    args = parser.parse_args()

    # Check if no arguments were provided
    if len(sys.argv) == 1:
        print(__doc__)  # Print ASCII art
        parser.print_help()  # Print help message
        sys.exit(1)  # Exit the script

    # Handling single hash string
    if args.single:
        with requests.Session() as session:
            results = {args.single: check_hash(args.single, session)}
    elif args.file:
        hash_values = read_csv(args.file)
        results = {}
        with requests.Session() as session:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                # Create a tqdm progress bar
                tasks = {executor.submit(check_hash, hash_value, session): hash_value for hash_value in hash_values}
                for future in tqdm(concurrent.futures.as_completed(tasks), total=len(tasks), desc="Processing"):
                    hash_value = tasks[future]
                    results[hash_value] = future.result()
    else:
        print("Error: Please provide a hash string or a path to a CSV file containing hashes.")
        exit(1)

    # Output results
    if args.output:
        file_extension = args.output.split('.')[-1].lower()
        if file_extension == 'csv':
            write_to_csv(args.output, results)
        elif file_extension == 'json':
            write_to_json(args.output, results)
        else:
            print("Error: Output file must have a .csv or .json extension")
            exit(1)
    else:
        print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()
