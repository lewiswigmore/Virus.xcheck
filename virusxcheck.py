import csv
import requests
import argparse
import json
import re

def read_csv(file_path):
    hashes = []
    hex_pattern = re.compile(r'\b[a-fA-F0-9]{32,64}\b')  # Regex pattern for 32 to 64 length hex strings
    with open(file_path, mode='r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            for value in row:
                match = hex_pattern.search(value)
                if match:
                    hashes.append(match.group())
    return hashes

def check_hash(hash_value):
    url = f"https://s3.us-east-1.wasabisys.com/vxugmwdb/{hash_value}"
    try:
        response = requests.head(url)  # Using HEAD to check the existence without downloading the file
        if response.status_code == 200:
            return url
        else:
            return None
    except requests.RequestException:
        return None

def main(file_path):
    hash_values = read_csv(file_path)
    results = {}
    for hash_value in hash_values:
        url = check_hash(hash_value)
        if url:
            results[hash_value] = {"url": url, "status": "Found"}
        else:
            results[hash_value] = {"status": "Not Found"}
    print(json.dumps(results, indent=4))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='VirusXCheck Tool')
    parser.add_argument('-f', '--file', required=True, help='Path to CSV file containing hashes')
    args = parser.parse_args()
    main(args.file)
