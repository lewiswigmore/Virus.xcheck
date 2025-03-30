"""
Test HTML report generation for Virus.xcheck
"""

import os
import sys
import json

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Test data with VirusTotal results
test_data = {
    "5d196e569651cc61b5958fbbe09c6bb10839bce838cbe69d456ceb94965db183": {
        "status": "Found in VX database",
        "details": {
            "type": "unknown",
            "size": 7127040,
            "first_seen": "2025-03-30T18:28:54Z",
            "names": ["suspicious_file.exe"]
        },
        "virustotal_url": "https://www.virustotal.com/gui/file/5d196e569651cc61b5958fbbe09c6bb10839bce838cbe69d456ceb94965db183",
        "vt_data": {
            "names": ["file1.exe", "malware.exe"],
            "size": 7127040,
            "type_description": "Win32 EXE",
            "first_submission_date": "2025-03-30 18:28:54",
            "last_analysis_date": "2025-03-30 18:30:00",
            "tags": ["spreader", "overlay", "peexe"],
            "last_analysis_stats": {
                "malicious": 59,
                "suspicious": 0,
                "undetected": 13,
                "timeout": 0,
                "failure": 5
            }
        }
    },
    "81d0dc0bfe3743d4b347087ef1d04b5eb1876fad39f841a3782342ea38375840": {
        "status": "Found in VX database",
        "details": {
            "type": "unknown",
            "size": 74240,
            "first_seen": "2025-03-30T18:28:52Z"
        },
        "virustotal_url": "https://www.virustotal.com/gui/file/81d0dc0bfe3743d4b347087ef1d04b5eb1876fad39f841a3782342ea38375840",
        "vt_data": {
            "names": ["sample.exe"],
            "size": 74240,
            "type_description": "Win32 EXE",
            "first_submission_date": "2025-03-30 18:28:52",
            "tags": ["spreader", "peexe"],
            "last_analysis_stats": {
                "malicious": 45,
                "suspicious": 5,
                "undetected": 20
            }
        }
    }
}

# Try importing the HTML reporter module
try:
    print("Attempting to import HTML reporter module...")
    from html_reporter import generate_html_report
    
    # Generate HTML report
    output_path = os.path.join(os.getcwd(), "test_html_report.html")
    print(f"Generating HTML report to: {output_path}")
    
    generate_html_report(test_data, output_path)
    print(f"Success! HTML report generated at: {output_path}")
    
except ImportError as e:
    print(f"Error importing HTML reporter module: {e}")
    
    # Check if the modules are installed
    print("\nChecking for required packages:")
    for package in ["jinja2", "plotly", "pandas"]:
        try:
            __import__(package)
            print(f"✓ {package} is installed")
        except ImportError:
            print(f"✗ {package} is NOT installed")
    
    print("\nTry installing the required packages with:")
    print("pip install jinja2 plotly pandas")
    
except Exception as e:
    print(f"Error generating HTML report: {type(e).__name__}: {e}")