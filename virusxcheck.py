"""

██╗   ██╗██╗██████╗ ██╗   ██╗███████╗   ██╗  ██╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
██║   ██║██║██╔══██╗██║   ██║██╔════╝   ╚██╗██╔╝██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
██║   ██║██║██████╔╝██║   ██║███████╗    ╚███╔╝ ██║     ███████║█████╗  ██║     █████╔╝ 
╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║    ██╔██╗ ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
 ╚████╔╝ ██║██║  ██║╚██████╔╝███████║██╗██╔╝ ██╗╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
                                                                                        
"""

# Suppress all Python warnings and informational messages
import os
import sys
import warnings

# Completely disable warnings and redirect stderr before importing other modules
warnings.filterwarnings("ignore")
# Create a null device to suppress stderr
original_stderr = sys.stderr
null_device = open(os.devnull, 'w')
sys.stderr = null_device

# Now import the rest of the modules
import csv
import requests
import argparse
import json
import re
import concurrent.futures
import colorama
from colorama import Fore, Back, Style
from tqdm import tqdm
from ratelimit import limits, sleep_and_retry
from pathlib import Path
from datetime import datetime
from tabulate import tabulate
from dotenv import load_dotenv

# Initialize colorama for cross-platform colored terminal text
colorama.init(autoreset=True)

# Configuration settings
API_BASE_URL = "https://virus.exchange/api"
VT_API_BASE_URL = "https://www.virustotal.com/api/v3"

# Load environment variables from .env file
load_dotenv()

# Get API keys from environment variables or command line
DEFAULT_API_KEY = os.getenv("VIRUSXCHECK_API_KEY", "")
DEFAULT_VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

def read_csv(file_path):
    """Read hashes from a CSV file"""
    hashes = []
    hex_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')  # Regex pattern for SHA256
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
        print(f"{Fore.RED}Error: File not found - {file_path}{Style.RESET_ALL}")
        exit(1)
    except Exception as e:
        print(f"{Fore.RED}An error occurred while reading the file: {e}{Style.RESET_ALL}")
        exit(1)

class VirusExchangeAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {api_key}"})
    
    @sleep_and_retry
    @limits(calls=15, period=1)
    def get_sample_details(self, sha256_hash):
        """Get sample details using the Virus.Exchange API"""
        url = f"{API_BASE_URL}/samples/{sha256_hash}"
        try:
            response = self.session.get(url)
            if response.status_code == 200:
                return {
                    "status": "Found in VX database",
                    "details": response.json(),
                    "virustotal_url": f"https://www.virustotal.com/gui/file/{sha256_hash}"
                }
            elif response.status_code == 404:
                return {
                    "status": "Not found in VX database", 
                    "virustotal_url": f"https://www.virustotal.com/gui/file/{sha256_hash}"
                }
            else:
                return {
                    "status": f"Error: HTTP {response.status_code}",
                    "virustotal_url": f"https://www.virustotal.com/gui/file/{sha256_hash}"
                }
        except requests.RequestException as e:
            return {
                "status": f"Request Error: {e}",
                "virustotal_url": f"https://www.virustotal.com/gui/file/{sha256_hash}"
            }
    
    def fallback_check(self, sha256_hash):
        """Fallback to the old method if API fails"""
        vx_url = f"https://s3.us-east-1.wasabisys.com/vxugmwdb/{sha256_hash}"
        virustotal_url = f"https://www.virustotal.com/gui/file/{sha256_hash}"
        
        try:
            response = self.session.head(vx_url)
            if response.status_code == 200:
                return {
                    "status": "Found in VX database (fallback check)",
                    "vx_url": vx_url,
                    "virustotal_url": virustotal_url
                }
            elif response.status_code == 404:
                return {
                    "status": "Not found in VX database",
                    "virustotal_url": virustotal_url
                }
            else:
                return {
                    "status": f"Error: HTTP {response.status_code}",
                    "vx_url": None,
                    "virustotal_url": virustotal_url
                }
        except requests.RequestException as e:
            return {
                "status": f"Request Error: {e}",
                "virustotal_url": virustotal_url
            }

class VirusTotalAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": api_key,
            "Accept": "application/json"
        })
    
    @sleep_and_retry
    @limits(calls=4, period=60)  # VT API rate limits: 4 requests per minute for standard API keys
    def get_file_report(self, file_hash):
        """Get file report using the VirusTotal API"""
        if not self.api_key:
            return None
            
        url = f"{VT_API_BASE_URL}/files/{file_hash}"
        try:
            response = self.session.get(url)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": "File not found on VirusTotal"}
            else:
                return {"error": f"HTTP {response.status_code}: {response.text}"}
        except requests.RequestException as e:
            return {"error": f"Request Error: {e}"}
    
    def extract_scan_results(self, vt_data):
        """Extract relevant information from VirusTotal API response"""
        if not vt_data or "error" in vt_data:
            return vt_data
            
        try:
            attributes = vt_data.get("data", {}).get("attributes", {})
            
            # Basic file information
            result = {
                "names": attributes.get("names", []),
                "size": attributes.get("size", 0),
                "type_description": attributes.get("type_description", "Unknown"),
                "first_submission_date": datetime.fromtimestamp(attributes.get("first_submission_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if attributes.get("first_submission_date") else "Unknown",
                "last_analysis_date": datetime.fromtimestamp(attributes.get("last_analysis_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if attributes.get("last_analysis_date") else "Unknown",
                "times_submitted": attributes.get("times_submitted", 0),
                "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                "popular_threat_classification": attributes.get("popular_threat_classification", {}),
                "tags": attributes.get("tags", []),
                "scan_results": {}
            }
            
            # Get full scan results from last analysis
            last_analysis = attributes.get("last_analysis_results", {})
            for engine, analysis in last_analysis.items():
                result["scan_results"][engine] = {
                    "category": analysis.get("category", "unknown"),
                    "result": analysis.get("result", None),
                    "method": analysis.get("method", "unknown"),
                    "engine_name": analysis.get("engine_name", engine),
                    "engine_version": analysis.get("engine_version", "unknown")
                }
                
            return result
        except Exception as e:
            return {"error": f"Error parsing VirusTotal data: {str(e)}"}

def check_hash(hash_value, api, vt_api=None):
    """Check a hash using the Virus.Exchange API with fallback and VirusTotal lookup"""
    result = {}
    
    # Validate hash length and type
    if len(hash_value) == 64:  # SHA-256
        try:
            # First check in Virus.Exchange
            vx_result = api.get_sample_details(hash_value)
            result = vx_result
            
            # If API fails, try fallback method
            if "Error" in result["status"]:
                vx_result = api.fallback_check(hash_value)
                result.update(vx_result)
                
            # Add VirusTotal data if API key is provided
            if vt_api:
                vt_data = vt_api.get_file_report(hash_value)
                vt_results = vt_api.extract_scan_results(vt_data)
                result["vt_data"] = vt_results
                
            return result
        except Exception as e:
            # If any exception occurs, use fallback and try VirusTotal if available
            result = api.fallback_check(hash_value)
            if vt_api:
                vt_data = vt_api.get_file_report(hash_value)
                vt_results = vt_api.extract_scan_results(vt_data)
                result["vt_data"] = vt_results
            return result
    
    # For other hash types (MD5, SHA-1, SHA-512)
    elif len(hash_value) in [32, 40, 128]:  # MD5, SHA-1, or SHA-512
        result = {"status": "Hash type not supported in VX database", "virustotal_url": f"https://www.virustotal.com/gui/file/{hash_value}"}
        # Still try VirusTotal for these hash types
        if vt_api:
            vt_data = vt_api.get_file_report(hash_value)
            vt_results = vt_api.extract_scan_results(vt_data)
            result["vt_data"] = vt_results
        return result
    
    # If hash length doesn't match known formats
    else:
        return {"status": "Invalid hash length", "virustotal_url": None}

def write_to_csv(file_path, data):
    """Write results to a CSV file with enhanced metadata including VirusTotal results"""
    with open(file_path, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        # Enhanced headers including VirusTotal data
        writer.writerow([
            'Hash', 'VX Status', 'File Type', 'Size', 'First Seen', 
            'Names', 'VX URL', 'Download Link', 'VirusTotal URL',
            'VT Detection Rate', 'VT Malicious', 'VT Suspicious', 'VT Clean', 
            'VT Type', 'VT First Seen', 'VT Tags'
        ])
        
        for hash_value, details in data.items():
            # Extract detailed information if available
            file_type = details.get('details', {}).get('type', 'N/A')
            size = details.get('details', {}).get('size', 'N/A')
            first_seen = details.get('details', {}).get('first_seen', 'N/A')
            names = ', '.join(details.get('details', {}).get('names', ['N/A']))
            download_link = details.get('details', {}).get('download_link', 'N/A')
            vx_url = details.get('vx_url', details.get('details', {}).get('download_link', 'N/A'))
            
            # Extract VirusTotal information if available
            vt_detection_rate = 'N/A'
            vt_malicious = 'N/A'
            vt_suspicious = 'N/A'
            vt_clean = 'N/A'
            vt_type = 'N/A'
            vt_first_seen = 'N/A'
            vt_tags = 'N/A'
            
            if 'vt_data' in details and details['vt_data'] and 'error' not in details['vt_data']:
                vt_data = details['vt_data']
                
                # Calculate detection rate
                if 'last_analysis_stats' in vt_data and vt_data['last_analysis_stats']:
                    stats = vt_data['last_analysis_stats']
                    total = sum(stats.values())
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    undetected = stats.get('undetected', 0)
                    
                    if total > 0:
                        vt_detection_rate = f"{(malicious + suspicious) / total:.1%}"
                        vt_malicious = str(malicious)
                        vt_suspicious = str(suspicious)
                        vt_clean = str(undetected)
                
                vt_type = vt_data.get('type_description', 'N/A')
                vt_first_seen = vt_data.get('first_submission_date', 'N/A')
                
                if 'tags' in vt_data and vt_data['tags']:
                    vt_tags = ', '.join(vt_data['tags'][:10])
                    if len(vt_data['tags']) > 10:
                        vt_tags += f" (+ {len(vt_data['tags']) - 10} more)"
            
            writer.writerow([
                hash_value, 
                details['status'], 
                file_type,
                size, 
                first_seen, 
                names,
                vx_url,
                download_link,
                details.get('virustotal_url', 'N/A'),
                vt_detection_rate,
                vt_malicious,
                vt_suspicious,
                vt_clean,
                vt_type,
                vt_first_seen,
                vt_tags
            ])

def write_to_json(file_path, data):
    """Write results to a JSON file"""
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def pretty_print_results(results):
    """Print results with nice formatting and colors"""
    print()
    print(f"{Fore.CYAN}{'═'*80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'VIRUS.XCHECK RESULTS':^80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*80}{Style.RESET_ALL}")
    print()
    
    for hash_value, details in results.items():
        status = details['status']
        
        # Set color based on status
        if "Found in VX database" in status:
            status_color = Fore.RED + Style.BRIGHT
            hash_color = Fore.RED
        elif "Not found" in status:
            status_color = Fore.GREEN
            hash_color = Fore.WHITE
        else:
            status_color = Fore.YELLOW
            hash_color = Fore.YELLOW
        
        # Print hash and status
        print(f"{hash_color}{Style.BRIGHT}Hash:{Style.RESET_ALL}{hash_color} {hash_value}{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}Status:{Style.RESET_ALL} {status_color}{status}{Style.RESET_ALL}")
        
        # Print additional details if available
        if 'details' in details and details['details']:
            det = details['details']
            
            # Create a table of metadata
            metadata = []
            if 'type' in det:
                metadata.append([f"{Style.BRIGHT}File Type{Style.RESET_ALL}", det.get('type', 'Unknown')])
            if 'size' in det:
                size = det.get('size', 0)
                size_str = f"{size:,} bytes ({size / 1024:.1f} KB)" if size else "Unknown"
                metadata.append([f"{Style.BRIGHT}Size{Style.RESET_ALL}", size_str])
            if 'first_seen' in det:
                metadata.append([f"{Style.BRIGHT}First Seen{Style.RESET_ALL}", det.get('first_seen', 'Unknown')])
            if 'sha1' in det:
                metadata.append([f"{Style.BRIGHT}SHA-1{Style.RESET_ALL}", det.get('sha1', 'Unknown')])
            if 'md5' in det:
                metadata.append([f"{Style.BRIGHT}MD5{Style.RESET_ALL}", det.get('md5', 'Unknown')])
            
            if metadata:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}File Metadata:{Style.RESET_ALL}")
                print(tabulate(metadata, tablefmt="simple"))
            
            # Show file names if available
            if 'names' in det and det['names']:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}Known File Names:{Style.RESET_ALL}")
                for i, name in enumerate(det['names']):
                    print(f"  {i+1}. {Fore.WHITE}{name}{Style.RESET_ALL}")
            
            # Show tags if available
            if 'tags' in det and det['tags']:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}Tags:{Style.RESET_ALL}")
                tags_str = ", ".join([f"{Fore.YELLOW}{tag}{Style.RESET_ALL}" for tag in det['tags']])
                print(f"  {tags_str}")
        
        # Display VirusTotal results if available
        if 'vt_data' in details and details['vt_data']:
            vt_data = details['vt_data']
            if 'error' in vt_data:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}VirusTotal Results:{Style.RESET_ALL} {Fore.YELLOW}{vt_data['error']}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}VirusTotal Results:{Style.RESET_ALL}")
                
                # Basic file information
                vt_metadata = []
                if 'type_description' in vt_data:
                    vt_metadata.append([f"{Style.BRIGHT}File Type{Style.RESET_ALL}", vt_data.get('type_description', 'Unknown')])
                if 'size' in vt_data:
                    size = vt_data.get('size', 0)
                    size_str = f"{size:,} bytes ({size / 1024:.1f} KB)" if size else "Unknown"
                    vt_metadata.append([f"{Style.BRIGHT}Size{Style.RESET_ALL}", size_str])
                if 'first_submission_date' in vt_data:
                    vt_metadata.append([f"{Style.BRIGHT}First Seen{Style.RESET_ALL}", vt_data.get('first_submission_date', 'Unknown')])
                if 'last_analysis_date' in vt_data:
                    vt_metadata.append([f"{Style.BRIGHT}Last Analysis{Style.RESET_ALL}", vt_data.get('last_analysis_date', 'Unknown')])
                if 'times_submitted' in vt_data:
                    vt_metadata.append([f"{Style.BRIGHT}Times Submitted{Style.RESET_ALL}", vt_data.get('times_submitted', 'Unknown')])
                
                if vt_metadata:
                    print(tabulate(vt_metadata, tablefmt="simple"))
                
                # Display file names
                if 'names' in vt_data and vt_data['names']:
                    print(f"\n{Fore.CYAN}{Style.BRIGHT}File Names on VirusTotal:{Style.RESET_ALL}")
                    for i, name in enumerate(vt_data['names'][:10]):  # Limit to 10 names
                        print(f"  {i+1}. {Fore.WHITE}{name}{Style.RESET_ALL}")
                    if len(vt_data['names']) > 10:
                        print(f"  ... and {len(vt_data['names']) - 10} more")
                
                # Display tags
                if 'tags' in vt_data and vt_data['tags']:
                    print(f"\n{Fore.CYAN}{Style.BRIGHT}VirusTotal Tags:{Style.RESET_ALL}")
                    tags_str = ", ".join([f"{Fore.YELLOW}{tag}{Style.RESET_ALL}" for tag in vt_data['tags'][:15]])
                    print(f"  {tags_str}")
                    if len(vt_data['tags']) > 15:
                        print(f"  ... and {len(vt_data['tags']) - 15} more")
                
                # Show detection statistics
                if 'last_analysis_stats' in vt_data and vt_data['last_analysis_stats']:
                    stats = vt_data['last_analysis_stats']
                    total = sum(stats.values())
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    undetected = stats.get('undetected', 0)
                    
                    detection_rate = (malicious + suspicious) / total if total > 0 else 0
                    print(f"\n{Fore.CYAN}{Style.BRIGHT}Detection Statistics:{Style.RESET_ALL}")
                    
                    # Choose color based on detection ratio
                    if detection_rate > 0.3:
                        det_color = Fore.RED
                    elif detection_rate > 0.1:
                        det_color = Fore.YELLOW
                    else:
                        det_color = Fore.GREEN
                    
                    print(f"  {det_color}{Style.BRIGHT}Detection Rate: {malicious + suspicious}/{total} ({detection_rate:.1%}){Style.RESET_ALL}")
                    print(f"  {Fore.RED}Malicious: {malicious}{Style.RESET_ALL}, {Fore.YELLOW}Suspicious: {suspicious}{Style.RESET_ALL}, {Fore.GREEN}Clean: {undetected}{Style.RESET_ALL}")
                    
                    # Display top detections
                    if 'scan_results' in vt_data and vt_data['scan_results']:
                        detections = [(engine, data) for engine, data in vt_data['scan_results'].items() 
                                     if data.get('category') in ['malicious', 'suspicious'] and data.get('result')]
                        if detections:
                            print(f"\n{Fore.CYAN}{Style.BRIGHT}Top Detections:{Style.RESET_ALL}")
                            detections.sort(key=lambda x: x[0])  # Sort by engine name
                            detection_table = []
                            for engine, data in detections[:10]:  # Show top 10
                                category_color = Fore.RED if data['category'] == 'malicious' else Fore.YELLOW
                                detection_table.append([
                                    f"{Style.BRIGHT}{engine}{Style.RESET_ALL}", 
                                    f"{category_color}{data.get('result', 'Unknown')}{Style.RESET_ALL}"
                                ])
                            print(tabulate(detection_table, headers=[f"{Style.BRIGHT}Engine{Style.RESET_ALL}", f"{Style.BRIGHT}Detection{Style.RESET_ALL}"], tablefmt="simple"))
                            if len(detections) > 10:
                                print(f"  ... and {len(detections) - 10} more detections")
        
        # Print URLs
        print(f"\n{Fore.CYAN}{Style.BRIGHT}Links:{Style.RESET_ALL}")
        if 'details' in details and details['details'] and 'download_link' in details['details']:
            print(f"  {Style.BRIGHT}Download:{Style.RESET_ALL} {Fore.BLUE}{details['details']['download_link']}{Style.RESET_ALL}")
        if 'virustotal_url' in details:
            print(f"  {Style.BRIGHT}VirusTotal:{Style.RESET_ALL} {Fore.BLUE}{details['virustotal_url']}{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}{'─'*80}{Style.RESET_ALL}\n")

def update_env_file(api_key):
    """Update the .env file with a new API key"""
    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    
    # Read existing content
    content = []
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            content = f.readlines()
    
    # Update or add the API key
    api_key_line = f"VIRUSXCHECK_API_KEY={api_key}\n"
    api_key_found = False
    
    for i, line in enumerate(content):
        if line.startswith("VIRUSXCHECK_API_KEY="):
            content[i] = api_key_line
            api_key_found = True
            break
    
    if not api_key_found:
        if content and not content[-1].endswith('\n'):
            content.append('\n')
        if content:
            content.append('# Virus.Exchange API Key\n')
        content.append(api_key_line)
    
    # Write back to file
    with open(env_file, 'w') as f:
        f.writelines(content)

def update_env_file_multiple(env_content):
    """Update the .env file with multiple API keys"""
    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    
    # Read existing content
    content = []
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            content = f.readlines()
    
    # Update or add the API keys
    for key, value in env_content.items():
        line = f"{key}={value}\n"
        key_found = False
        
        for i, existing_line in enumerate(content):
            if existing_line.startswith(f"{key}="):
                content[i] = line
                key_found = True
                break
        
        if not key_found:
            if content and not content[-1].endswith('\n'):
                content.append('\n')
            if content:
                content.append(f'# {key} API Key\n')
            content.append(line)
    
    # Write back to file
    with open(env_file, 'w') as f:
        f.writelines(content)

def main():
    # Restore stderr only for controlled output
    try:
        # First save original args for later use to avoid potential stderr output
        args_copy = sys.argv.copy()
        
        parser = argparse.ArgumentParser(description='Virus.xcheck CLI Tool')
        # Original options
        parser.add_argument('-f', '--file', help='Path to CSV file containing hashes')
        parser.add_argument('-o', '--output', help='Path to output file (CSV or JSON format)')
        parser.add_argument('-s', '--single', help='Single hash string to check')
        
        # API key options
        parser.add_argument('-k', '--apikey', help='Virus.Exchange API key')
        parser.add_argument('--vt-apikey', help='VirusTotal API key')
        parser.add_argument('--save-config', action='store_true', help='Save API keys to .env file')
        parser.add_argument('--no-color', action='store_true', help='Disable colored output')
        
        # Parse args with stderr still redirected to null_device
        args = parser.parse_args(args_copy[1:])
        
        # Now we can safely restore stderr for our controlled output
        sys.stderr = original_stderr
        
        # Check if no arguments were provided
        if len(args_copy) == 1:
            print(__doc__)  # Print ASCII art
            parser.print_help()  # Print help message
            sys.exit(1)  # Exit the script
        
        # Disable colors if requested
        if args.no_color:
            colorama.deinit()
        
        # Get API keys from command line or .env file
        api_key = args.apikey if args.apikey else DEFAULT_API_KEY
        vt_api_key = args.vt_apikey if args.vt_apikey else DEFAULT_VT_API_KEY
        
        if not api_key:
            print(f"{Fore.RED}Error: No Virus.Exchange API key provided. Please specify an API key using the -k/--apikey option or add it to the .env file.{Style.RESET_ALL}")
            sys.exit(1)
        
        # Save API keys to .env file if requested
        if args.save_config:
            env_content = {}
            if args.apikey:
                env_content["VIRUSXCHECK_API_KEY"] = args.apikey
            if args.vt_apikey:
                env_content["VIRUSTOTAL_API_KEY"] = args.vt_apikey
            
            if env_content:
                update_env_file_multiple(env_content)
                print(f"{Fore.GREEN}API key(s) saved to .env file{Style.RESET_ALL}")
        
        # Initialize API client
        api = VirusExchangeAPI(api_key)
        
        # Initialize VirusTotal API client if API key is provided
        vt_api = None
        if vt_api_key:
            vt_api = VirusTotalAPI(vt_api_key)
            print(f"{Fore.GREEN}VirusTotal API integration enabled{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}VirusTotal API integration disabled. Use --vt-apikey to enable.{Style.RESET_ALL}")
        
        try:
            # Handle single hash string
            if args.single:
                results = {args.single: check_hash(args.single, api, vt_api)}
            # Handle CSV file with hashes
            elif args.file:
                hash_values = read_csv(args.file)
                results = {}
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    # Create a tqdm progress bar
                    tasks = {executor.submit(check_hash, hash_value, api, vt_api): hash_value for hash_value in hash_values}
                    for future in tqdm(concurrent.futures.as_completed(tasks), total=len(tasks), desc="Processing"):
                        hash_value = tasks[future]
                        results[hash_value] = future.result()
            else:
                print(f"{Fore.RED}Error: Please provide a hash string or a path to a CSV file containing hashes.{Style.RESET_ALL}")
                exit(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Operation cancelled by user. Exiting.{Style.RESET_ALL}")
            sys.exit(0)

        # Output results
        if args.output:
            file_extension = args.output.split('.')[-1].lower()
            if file_extension == 'csv':
                write_to_csv(args.output, results)
                print(f"{Fore.GREEN}Results saved to {args.output}{Style.RESET_ALL}")
            elif file_extension == 'json':
                write_to_json(args.output, results)
                print(f"{Fore.GREEN}Results saved to {args.output}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Error: Output file must have a .csv or .json extension{Style.RESET_ALL}")
                exit(1)
        else:
            # Pretty print the results to the console
            pretty_print_results(results)

    finally:
        # Always restore stderr at the end
        sys.stderr = original_stderr
        # Close the null device
        null_device.close()

if __name__ == "__main__":
    main()
