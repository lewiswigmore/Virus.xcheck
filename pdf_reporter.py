"""
PDF Report Generator for Virus.xcheck
This module generates professional PDF reports with scan results
"""

import os
from datetime import datetime
from fpdf2 import FPDF
import pandas as pd
import tempfile
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm


class VirusXcheckPDF(FPDF):
    """Custom PDF class with headers and footers"""
    
    def __init__(self):
        super().__init__()
        self.WIDTH = 210
        self.HEIGHT = 297
        
    def header(self):
        """Create header with logo and title"""
        # Logo (if exists)
        logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logo.png')
        if os.path.exists(logo_path):
            self.image(logo_path, 10, 8, 33)
            self.set_font('helvetica', 'B', 20)
            self.cell(40)  # Move to the right of the logo
        else:
            self.set_font('helvetica', 'B', 20)
            
        # Title
        self.set_text_color(45, 62, 80)  # Dark blue color
        self.cell(130, 10, 'Virus.xcheck Malware Analysis Report', 0, 1, 'C')
        
        # Timestamp
        self.set_font('helvetica', 'I', 10)
        self.cell(0, 10, f'Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 0, 'R')
        
        # Line break
        self.ln(20)
        
    def footer(self):
        """Create footer with page numbers"""
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'C')
        self.cell(0, 10, f'Virus.xcheck © {datetime.now().year}', 0, 0, 'R')


class PDFReporter:
    """Creates professional PDF reports from hash analysis results"""
    
    def __init__(self):
        """Initialize the PDF reporter"""
        self.pdf = VirusXcheckPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)
        self.pdf.add_page()
        self.pdf.alias_nb_pages()
        
    def add_summary_section(self, results):
        """Add summary section with statistics"""
        # Calculate summary statistics
        total_hashes = len(results)
        vx_found = sum(1 for details in results.values() if 'Found in VX database' in details['status'])
        vx_not_found = total_hashes - vx_found
        with_vt_data = sum(1 for details in results.values() 
                          if 'vt_data' in details and details['vt_data'] and 'error' not in details['vt_data'])
        
        # Detection statistics
        malicious_count = 0
        suspicious_count = 0
        clean_count = 0
        total_samples = 0
        
        for details in results.values():
            if 'vt_data' in details and details['vt_data'] and 'last_analysis_stats' in details['vt_data']:
                stats = details['vt_data']['last_analysis_stats']
                malicious_count += stats.get('malicious', 0)
                suspicious_count += stats.get('suspicious', 0)
                clean_count += stats.get('undetected', 0)
                total_samples += 1
        
        # Add summary heading
        self.pdf.set_font('helvetica', 'B', 16)
        self.pdf.set_text_color(45, 62, 80)
        self.pdf.cell(0, 10, 'Analysis Summary', 0, 1, 'L')
        self.pdf.ln(2)
        
        # Summary text
        self.pdf.set_font('helvetica', '', 10)
        self.pdf.set_text_color(0, 0, 0)
        self.pdf.cell(0, 6, f'Total hashes analyzed: {total_hashes}', 0, 1)
        self.pdf.cell(0, 6, f'Found in Virus.Exchange: {vx_found}', 0, 1)
        self.pdf.cell(0, 6, f'Not found in Virus.Exchange: {vx_not_found}', 0, 1)
        self.pdf.cell(0, 6, f'With VirusTotal data: {with_vt_data}', 0, 1)
        self.pdf.ln(5)
        
        # Add detection statistics if available
        if total_samples > 0:
            self.pdf.set_font('helvetica', 'B', 12)
            self.pdf.cell(0, 8, 'Detection Statistics', 0, 1, 'L')
            self.pdf.ln(2)
            
            self.pdf.set_font('helvetica', '', 10)
            self.pdf.cell(0, 6, f'Average detections per sample: {malicious_count / total_samples:.1f}', 0, 1)
            
            # Create a detection summary table
            self.pdf.set_draw_color(45, 62, 80)
            self.pdf.set_line_width(0.3)
            
            # Table header
            self.pdf.set_font('helvetica', 'B', 10)
            self.pdf.set_fill_color(240, 240, 240)
            self.pdf.cell(50, 8, 'Category', 1, 0, 'C', True)
            self.pdf.cell(30, 8, 'Count', 1, 0, 'C', True)
            self.pdf.cell(50, 8, 'Percentage', 1, 1, 'C', True)
            
            # Table data
            self.pdf.set_font('helvetica', '', 10)
            total_detections = malicious_count + suspicious_count + clean_count
            
            # Malicious row
            self.pdf.set_fill_color(254, 240, 240)
            self.pdf.cell(50, 8, 'Malicious', 1, 0, 'L', True)
            self.pdf.cell(30, 8, str(malicious_count), 1, 0, 'R', True)
            percentage = (malicious_count / total_detections * 100) if total_detections > 0 else 0
            self.pdf.cell(50, 8, f'{percentage:.1f}%', 1, 1, 'R', True)
            
            # Suspicious row
            self.pdf.set_fill_color(255, 250, 240)
            self.pdf.cell(50, 8, 'Suspicious', 1, 0, 'L', True)
            self.pdf.cell(30, 8, str(suspicious_count), 1, 0, 'R', True)
            percentage = (suspicious_count / total_detections * 100) if total_detections > 0 else 0
            self.pdf.cell(50, 8, f'{percentage:.1f}%', 1, 1, 'R', True)
            
            # Clean row
            self.pdf.set_fill_color(240, 255, 240)
            self.pdf.cell(50, 8, 'Clean', 1, 0, 'L', True)
            self.pdf.cell(30, 8, str(clean_count), 1, 0, 'R', True)
            percentage = (clean_count / total_detections * 100) if total_detections > 0 else 0
            self.pdf.cell(50, 8, f'{percentage:.1f}%', 1, 1, 'R', True)
        
        self.pdf.ln(8)

    def add_detailed_results(self, results):
        """Add detailed results for each hash"""
        # Section header
        self.pdf.set_font('helvetica', 'B', 16)
        self.pdf.set_text_color(45, 62, 80)
        self.pdf.cell(0, 10, 'Detailed Results', 0, 1, 'L')
        self.pdf.ln(2)
        
        # For each hash
        for hash_value, details in results.items():
            # Check if we need a new page
            if self.pdf.get_y() > 240:
                self.pdf.add_page()
            
            # Hash header with status color
            self.pdf.set_font('helvetica', 'B', 12)
            if 'Found in VX database' in details['status']:
                self.pdf.set_text_color(231, 76, 60)  # Red for malicious
            elif 'Not found' in details['status']:
                self.pdf.set_text_color(46, 204, 113)  # Green for clean
            else:
                self.pdf.set_text_color(149, 165, 166)  # Gray for unknown
            
            self.pdf.cell(0, 8, hash_value, 0, 1, 'L')
            
            # Status
            self.pdf.set_font('helvetica', 'B', 10)
            self.pdf.set_text_color(0, 0, 0)
            self.pdf.cell(20, 6, 'Status:', 0, 0)
            self.pdf.set_font('helvetica', '', 10)
            self.pdf.cell(0, 6, details['status'], 0, 1)
            
            # VT data if available
            if 'vt_data' in details and details['vt_data'] and 'error' not in details['vt_data']:
                vt_data = details['vt_data']
                
                # File info
                if 'type_description' in vt_data:
                    self.pdf.set_font('helvetica', 'B', 10)
                    self.pdf.cell(20, 6, 'Type:', 0, 0)
                    self.pdf.set_font('helvetica', '', 10)
                    self.pdf.cell(0, 6, vt_data['type_description'], 0, 1)
                
                if 'size' in vt_data:
                    size = vt_data['size']
                    size_str = f"{size:,} bytes ({size / 1024:.1f} KB)"
                    self.pdf.set_font('helvetica', 'B', 10)
                    self.pdf.cell(20, 6, 'Size:', 0, 0)
                    self.pdf.set_font('helvetica', '', 10)
                    self.pdf.cell(0, 6, size_str, 0, 1)
                
                if 'first_submission_date' in vt_data:
                    self.pdf.set_font('helvetica', 'B', 10)
                    self.pdf.cell(20, 6, 'First Seen:', 0, 0)
                    self.pdf.set_font('helvetica', '', 10)
                    self.pdf.cell(0, 6, vt_data['first_submission_date'], 0, 1)
                
                # Detection stats
                if 'last_analysis_stats' in vt_data:
                    stats = vt_data['last_analysis_stats']
                    total = sum(stats.values())
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    
                    if total > 0:
                        detection_rate = (malicious + suspicious) / total
                        
                        self.pdf.set_font('helvetica', 'B', 10)
                        self.pdf.cell(35, 6, 'Detection Rate:', 0, 0)
                        self.pdf.set_font('helvetica', '', 10)
                        
                        # Set color based on detection rate
                        if detection_rate > 0.5:
                            self.pdf.set_text_color(231, 76, 60)  # Red for high detection
                        elif detection_rate > 0.2:
                            self.pdf.set_text_color(243, 156, 18)  # Orange for medium
                        else:
                            self.pdf.set_text_color(46, 204, 113)  # Green for low
                            
                        self.pdf.cell(0, 6, f"{malicious + suspicious}/{total} ({detection_rate:.1%})", 0, 1)
                        self.pdf.set_text_color(0, 0, 0)  # Reset color
                
                # Tags
                if 'tags' in vt_data and vt_data['tags']:
                    self.pdf.set_font('helvetica', 'B', 10)
                    self.pdf.cell(20, 6, 'Tags:', 0, 0)
                    self.pdf.set_font('helvetica', '', 9)
                    
                    # Format tags with commas
                    tags_text = ', '.join(vt_data['tags'][:10])
                    if len(vt_data['tags']) > 10:
                        tags_text += f" (+ {len(vt_data['tags']) - 10} more)"
                        
                    self.pdf.multi_cell(0, 6, tags_text)
            
            # Links
            self.pdf.set_font('helvetica', 'B', 10)
            self.pdf.cell(20, 6, 'Links:', 0, 0)
            self.pdf.set_font('helvetica', '', 9)
            self.pdf.set_text_color(52, 152, 219)  # Blue for links
            
            if 'virustotal_url' in details:
                self.pdf.cell(0, 6, 'VirusTotal', 0, 1, 'L', False, details['virustotal_url'])
            
            if 'details' in details and details['details'] and 'download_link' in details['details']:
                self.pdf.cell(20, 6, '', 0, 0)
                self.pdf.cell(0, 6, 'Download Sample', 0, 1, 'L', False, details['details']['download_link'])
            
            # Reset text color
            self.pdf.set_text_color(0, 0, 0)
            
            # Add line break between entries
            self.pdf.ln(5)
            self.pdf.line(10, self.pdf.get_y(), 200, self.pdf.get_y())
            self.pdf.ln(8)
    
    def generate_report(self, results, output_file):
        """Generate the full PDF report"""
        # Add summary section
        self.add_summary_section(results)
        
        # Add detailed results
        self.add_detailed_results(results)
        
        # Save the PDF
        self.pdf.output(output_file)
        return output_file


# Function to use from main application
def generate_pdf_report(results, output_file):
    """Generate a PDF report from results"""
    reporter = PDFReporter()
    return reporter.generate_report(results, output_file)