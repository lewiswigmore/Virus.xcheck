"""
Test script for HTML and PDF report generation features
"""

import json
import os
from html_reporter import generate_html_report
from pdf_reporter import generate_pdf_report

def load_test_data():
    """Load test data from JSON file"""
    try:
        # First try to load from test_export.json which contains processed results
        with open('test_export.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # If that fails, create a minimal test result
        print("Creating sample test data...")
        return {
            "5d196e569651cc61b5958fbbe09c6bb10839bce838cbe69d456ceb94965db183": {
                "status": "Found in VX database",
                "details": {
                    "type": "unknown",
                    "size": 7127040,
                    "first_seen": "2025-03-30T18:28:54Z",
                    "sha1": "0393fd165a9074062ca276baf543f9fd0ef89820",
                    "md5": "99011c2ccfd52c9cdc09194a2d71fd3c",
                    "names": ["suspicious_file.exe"],
                    "download_link": "https://example.com/sample"
                },
                "virustotal_url": "https://www.virustotal.com/gui/file/5d196e569651cc61b5958fbbe09c6bb10839bce838cbe69d456ceb94965db183",
                "vt_data": {
                    "names": ["file1.exe", "malware.exe"],
                    "size": 7127040,
                    "type_description": "Win32 EXE",
                    "first_submission_date": "2025-03-30 18:28:54",
                    "last_analysis_date": "2025-03-30 18:30:00",
                    "times_submitted": 5,
                    "tags": ["spreader", "overlay", "peexe"],
                    "last_analysis_stats": {
                        "malicious": 59,
                        "suspicious": 0,
                        "undetected": 13,
                        "timeout": 0,
                        "failure": 5
                    },
                    "scan_results": {
                        "Engine1": {
                            "category": "malicious",
                            "result": "Trojan.Win32.Generic"
                        },
                        "Engine2": {
                            "category": "clean",
                            "result": None
                        }
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

def main():
    """Generate test reports"""
    # Load test data
    test_data = load_test_data()
    
    # Define output filenames
    html_output = os.path.join(os.getcwd(), "test_report.html")
    pdf_output = os.path.join(os.getcwd(), "test_report.pdf")
    
    print(f"Generating HTML report: {html_output}")
    try:
        generate_html_report(test_data, html_output)
        print(f"HTML report generated successfully!")
    except Exception as e:
        print(f"Error generating HTML report: {e}")
    
    print(f"\nGenerating PDF report: {pdf_output}")
    try:
        generate_pdf_report(test_data, pdf_output)
        print(f"PDF report generated successfully!")
    except Exception as e:
        print(f"Error generating PDF report: {e}")

if __name__ == "__main__":
    main()