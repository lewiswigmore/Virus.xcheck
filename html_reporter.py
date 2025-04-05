"""
HTML Report Generator for Virus.xcheck
This module generates interactive HTML reports with charts for hash analysis results
"""

import os
import json
import pandas as pd
import plotly.graph_objects as go
import plotly.io as pio
from plotly.subplots import make_subplots
from jinja2 import Environment, FileSystemLoader
from datetime import datetime

# Define HTML template
HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Virus.xcheck Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px 5px 0 0;
            margin-bottom: 20px;
        }
        .summary {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .chart-container {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .chart-grid {
            display: grid;
            grid-template-columns: repeat(1, 1fr);
            gap: 20px;
        }
        .chart-full {
            grid-column: span 1;
        }
        .result-item {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 15px;
        }
        .malicious {
            border-left: 5px solid #e74c3c;
        }
        .clean {
            border-left: 5px solid #2ecc71;
        }
        .suspicious {
            border-left: 5px solid #f39c12;
        }
        .unknown {
            border-left: 5px solid #95a5a6;
        }
        .metadata {
            display: flex;
            flex-wrap: wrap;
        }
        .metadata-item {
            margin-right: 20px;
            margin-bottom: 10px;
        }
        .metadata-label {
            font-weight: bold;
            color: #7f8c8d;
        }
        .detections {
            margin-top: 15px;
        }
        .tag {
            display: inline-block;
            background-color: #3498db;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            margin-right: 5px;
            margin-bottom: 5px;
            font-size: 12px;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            color: #7f8c8d;
            font-size: 12px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 8px 12px;
            text-align: left;
            border-bottom: 1px solid #e1e1e1;
        }
        th {
            background-color: #f2f2f2;
            font-weight: 600;
        }
        .section-description {
            margin-bottom: 20px;
            color: #555;
            line-height: 1.5;
        }
        .help-text {
            font-style: italic;
            color: #666;
            font-size: 0.9em;
            margin-top: 5px;
        }
        @media (max-width: 768px) {
            .chart-grid {
                grid-template-columns: 1fr;
            }
            .chart-full {
                grid-column: span 1;
            }
        }
    </style>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Virus.xcheck Analysis Report</h1>
            <p>Generated on: {{ timestamp }}</p>
        </div>
        
        <div class="summary">
            <h2>Analysis Summary</h2>
            <p class="section-description">
                This section provides an overview of the hash analysis results, showing how many samples were found in the Virus.Exchange database
                and how many have associated VirusTotal data. Samples found in the VX database are confirmed malware samples.
            </p>
            <p>Total hashes analysed: {{ total_hashes }}</p>
            <div class="metadata">
                <div class="metadata-item">
                    <span class="metadata-label">Found in Virus.Exchange:</span> {{ vx_found }}
                    <p class="help-text">Samples present in the malware repository</p>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Not found in Virus.Exchange:</span> {{ vx_not_found }}
                    <p class="help-text">Samples not present in the malware repository</p>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">With VirusTotal data:</span> {{ with_vt_data }}
                    <p class="help-text">Samples with additional analysis from VirusTotal</p>
                </div>
            </div>
        </div>
        
        <div class="chart-container chart-full">
            <h2>Detection Overview</h2>
            <p class="section-description">
                This chart shows the detection results for each analysed hash, with stacked bars indicating malicious, suspicious, and clean verdicts
                from antivirus engines. Higher malicious (red) and suspicious (orange) counts indicate stronger confidence that the file is malware.
                You can click on a hash in this chart to navigate to its detailed analysis below.
            </p>
            <div id="detection_chart" style="width: 100%; height: 400px;"></div>
        </div>
        
        <div class="chart-container chart-full">
            <h2>Detection Distribution</h2>
            <p class="section-description">
                This gauge chart visualizes the average malware detection rate across all samples. The needle position and color zones 
                indicate confidence levels in malicious classification (green: low, yellow: medium, orange: high, red: very high).
                The threshold line shows the maximum detection rate in your dataset.
            </p>
            <div id="distribution_chart" style="width: 100%; height: 450px;"></div>
        </div>
        
        {% if most_common_tags %}
        <div class="chart-container chart-full">
            <h2>Common Malware Tags</h2>
            <p class="section-description">
                This chart displays the most frequently occurring malware tags across all samples. These tags indicate specific
                behaviors, techniques, or classifications identified by analysis engines. Common tags like "trojan", "backdoor",
                or "ransomware" help classify the type of threats in your dataset.
            </p>
            <div id="tags_chart" style="width: 100%; height: 450px;"></div>
        </div>
        {% endif %}
        
        <h2>Detailed Results</h2>
        <p class="section-description">
            This section provides detailed information about each analysed hash, including its detection status, file metadata,
            detection statistics, and behavioural tags. Red-bordered items indicate files found in the malware database,
            while green-bordered items were not found in the database. Click the links at the bottom of each item to view
            the sample on VirusTotal or download it for further analysis.
        </p>
        
        {% for hash, details in results.items() %}
            <div class="result-item 
                {% if 'Found in VX database' in details.status %}malicious
                {% elif 'Not found' in details.status %}clean
                {% else %}unknown{% endif %}" id="{{ hash }}">
                <h3>Hash: {{ hash }}</h3>
                <p><strong>Status:</strong> {{ details.status }}</p>
                
                {% if details.get('vt_data') %}
                <div class="metadata">
                    {% if details.vt_data.get('type_description') %}
                    <div class="metadata-item">
                        <span class="metadata-label">File Type:</span> {{ details.vt_data.type_description }}
                    </div>
                    {% endif %}
                    
                    {% if details.vt_data.get('size') %}
                    <div class="metadata-item">
                        <span class="metadata-label">Size:</span> {{ details.vt_data.size|filesizeformat }}
                    </div>
                    {% endif %}
                    
                    {% if details.vt_data.get('first_submission_date') %}
                    <div class="metadata-item">
                        <span class="metadata-label">First Seen:</span> {{ details.vt_data.first_submission_date }}
                        <p class="help-text">When this sample was first submitted to VirusTotal</p>
                    </div>
                    {% endif %}
                    
                    {% if details.vt_data.get('times_submitted') %}
                    <div class="metadata-item">
                        <span class="metadata-label">Times Submitted:</span> {{ details.vt_data.times_submitted }}
                        <p class="help-text">How often this file has been uploaded for analysis</p>
                    </div>
                    {% endif %}
                </div>
                
                {% if details.vt_data.get('last_analysis_stats') %}
                <div class="detections">
                    <h4>Detection Statistics:</h4>
                    <p class="help-text">How antivirus engines classified this sample during analysis</p>
                    {% set stats = details.vt_data.last_analysis_stats %}
                    {% set total = stats.values()|sum %}
                    {% set malicious = stats.get('malicious', 0) %}
                    {% set suspicious = stats.get('suspicious', 0) %}
                    <p>
                        Detection Rate: {{ malicious + suspicious }}/{{ total }} 
                        ({{ ((malicious + suspicious) / total * 100)|round(1) }}%)
                    </p>
                    <ul>
                        <li>Malicious: {{ malicious }}</li>
                        <li>Suspicious: {{ suspicious }}</li>
                        <li>Clean: {{ stats.get('undetected', 0) }}</li>
                    </ul>
                </div>
                {% endif %}
                
                {% if details.vt_data.get('tags') %}
                <div>
                    <h4>Tags:</h4>
                    <p class="help-text">Behavioural and classification tags identified during analysis</p>
                    <p>
                    {% for tag in details.vt_data.tags %}
                        <span class="tag">{{ tag }}</span>
                    {% endfor %}
                    </p>
                </div>
                {% endif %}
                
                {% endif %}

                <p>
                    <a href="{{ details.get('virustotal_url', '#') }}" target="_blank">View on VirusTotal</a>
                    {% if details.get('details', {}).get('download_link') %}
                    | <a href="{{ details.details.download_link }}" target="_blank">Download Sample</a>
                    {% endif %}
                </p>
            </div>
        {% endfor %}
        
        <div class="footer">
            <p>Generated by Virus.xcheck | © {{ current_year }}</p>
            <p>This HTML report can be saved as PDF using your browser's print function (Ctrl+P)</p>
        </div>
    </div>
    
    {{ detection_chart_js|safe }}
    {{ distribution_chart_js|safe }}
    {{ tags_chart_js|safe }}
</body>
</html>"""


def jinja_filesizeformat_filter(value, binary=False):
    """Format file sizes for Jinja2 template"""
    if value is None or value == 'N/A':
        return "Unknown"
    
    value = float(value)
    base = 1024 if binary else 1000
    
    if value < base:
        return f"{value} bytes"
    elif value < base * base:
        return f"{value / base:.1f} KB"
    elif value < base * base * base:
        return f"{value / (base * base):.1f} MB"
    else:
        return f"{value / (base * base * base):.1f} GB"


class HTMLReporter:
    def __init__(self):
        """Initialize the HTML reporter"""
        self.env = Environment(autoescape=True)
        self.env.filters['filesizeformat'] = jinja_filesizeformat_filter
        self.template = self.env.from_string(HTML_TEMPLATE)
    
    def create_detection_chart(self, results):
        """Create a bar chart for detection rates"""
        data = []
        
        # Extract detection data from results
        for hash_value, details in results.items():
            if 'vt_data' in details and details['vt_data'] and 'last_analysis_stats' in details['vt_data']:
                stats = details['vt_data']['last_analysis_stats']
                total = sum(stats.values())
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                undetected = stats.get('undetected', 0)
                
                # Truncate hash for display
                short_hash = hash_value[:8] + '...'
                
                # Calculate detection rate percentage
                if total > 0:
                    detection_rate = (malicious + suspicious) / total * 100
                    data.append({
                        'hash': short_hash,
                        'full_hash': hash_value,
                        'detection_rate': detection_rate,
                        'malicious': malicious,
                        'suspicious': suspicious,
                        'clean': undetected,
                        'total': total
                    })
        
        if not data:
            return "document.getElementById('detection_chart').innerHTML = 'No detection data available';"
        
        # Sort data by detection rate
        data.sort(key=lambda x: x['detection_rate'], reverse=True)
        
        # Create a bar chart
        fig = go.Figure()
        
        # Add malicious and suspicious traces
        fig.add_trace(go.Bar(
            x=[d['hash'] for d in data],
            y=[d['malicious'] for d in data],
            name='Malicious',
            marker_color='#e74c3c'
        ))
        
        fig.add_trace(go.Bar(
            x=[d['hash'] for d in data],
            y=[d['suspicious'] for d in data],
            name='Suspicious',
            marker_color='#f39c12'
        ))
        
        fig.add_trace(go.Bar(
            x=[d['hash'] for d in data],
            y=[d['clean'] for d in data],
            name='Clean',
            marker_color='#2ecc71'
        ))
        
        # Update layout
        fig.update_layout(
            title='Detection Results by Hash',
            xaxis_title='Hash',
            yaxis_title='Number of Detections',
            barmode='stack',
            hovermode='closest',
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            ),
            margin=dict(l=50, r=50, t=80, b=50)
        )
        
        # Convert to HTML
        chart_js = f"""
        <script>
            var detection_data = {pio.to_json(fig)};
            Plotly.newPlot('detection_chart', detection_data.data, detection_data.layout);
            
            // Add click event for hash navigation
            document.getElementById('detection_chart').on('plotly_click', function(data) {{
                var hash_idx = data.points[0].pointIndex;
                var hash_list = {json.dumps([d['full_hash'] for d in data])};
                var hash_id = hash_list[hash_idx];
                var element = document.getElementById(hash_id);
                if (element) {{
                    element.scrollIntoView({{ behavior: 'smooth' }});
                }}
            }});
        </script>
        """
        
        return chart_js
    
    def create_distribution_chart(self, results):
        """Create a gauge chart for detection rates distribution, providing better visualization of malicious presence"""
        detection_rates = []
        
        # Extract detection rates
        for _, details in results.items():
            if 'vt_data' in details and details['vt_data'] and 'last_analysis_stats' in details['vt_data']:
                stats = details['vt_data']['last_analysis_stats']
                total = sum(stats.values())
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                
                if total > 0:
                    detection_rate = (malicious + suspicious) / total * 100
                    detection_rates.append(detection_rate)
        
        if not detection_rates:
            return "document.getElementById('distribution_chart').innerHTML = 'No detection data available';"
            
        # Calculate average detection rate and other statistics
        avg_detection_rate = sum(detection_rates) / len(detection_rates) if detection_rates else 0
        max_detection_rate = max(detection_rates) if detection_rates else 0
        min_detection_rate = min(detection_rates) if detection_rates else 0
        
        # Create a gauge chart showing average detection rate with reduced spacing
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=avg_detection_rate,
            title={
                "text": "Average Detection Rate",
                "font": {"size": 20},
                "align": "center"
            },
            number={
                "font": {"size": 40, "color": "#e74c3c" if avg_detection_rate > 50 else "#f39c12"},
                "suffix": "%", 
                "valueformat": ".1f"  # Format to 1 decimal place
            },
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickfont": {"size": 14}},
                "bar": {"color": "#e74c3c" if avg_detection_rate > 50 else "#f39c12"},
                "bgcolor": "white",
                "borderwidth": 2,
                "bordercolor": "gray",
                "steps": [
                    {"range": [0, 25], "color": "#2ecc71"},  # Green for low detection
                    {"range": [25, 50], "color": "#f1c40f"},  # Yellow for medium detection
                    {"range": [50, 75], "color": "#f39c12"},  # Orange for high detection
                    {"range": [75, 100], "color": "#e74c3c"}   # Red for very high detection
                ],
                "threshold": {
                    "line": {"color": "darkred", "width": 4},
                    "thickness": 0.75,
                    "value": max_detection_rate
                },
                "shape": "angular"
            },
            domain={"y": [0.1, 1], "x": [0.1, 0.9]}  # Adjust vertical positioning to reduce space
        ))
        
        # Create single interpretation with stats included
        if avg_detection_rate < 25:
            risk_level = "Low risk"
        elif avg_detection_rate < 50:
            risk_level = "Medium risk"
        elif avg_detection_rate < 75:
            risk_level = "High risk"
        else:
            risk_level = "Critical risk"
            
        # Combined stats and interpretation in a single annotation
        combined_text = f"{risk_level} • Min: {min_detection_rate:.1f}% • Max: {max_detection_rate:.1f}% • Samples: {len(detection_rates)}"
        
        # Add as a subtitle below gauge
        fig.update_layout(
            annotations=[
                dict(
                    x=0.5,
                    y=0,  # Position at bottom of chart
                    xref="paper",
                    yref="paper",
                    text=combined_text,
                    showarrow=False,
                    font=dict(size=14, color="#333"),
                    bgcolor="rgba(255, 255, 255, 0.8)",
                    borderpad=4
                )
            ],
            margin=dict(l=30, r=30, t=50, b=80),  # Reduced top margin
            height=450  # Slightly reduced height to compact elements
        )
        
        # Convert to HTML
        chart_js = f"""
        <script>
            var distribution_data = {pio.to_json(fig)};
            Plotly.newPlot('distribution_chart', distribution_data.data, distribution_data.layout);
        </script>
        """
        
        return chart_js
    
    def create_tags_chart(self, results):
        """Create a bar chart for common tags"""
        # Collect all tags
        all_tags = {}
        for _, details in results.items():
            if 'vt_data' in details and details['vt_data'] and 'tags' in details['vt_data']:
                for tag in details['vt_data']['tags']:
                    all_tags[tag] = all_tags.get(tag, 0) + 1
        
        if not all_tags:
            return "document.getElementById('tags_chart').innerHTML = 'No tag data available';"
        
        # Sort tags by frequency
        sorted_tags = sorted(all_tags.items(), key=lambda x: x[1], reverse=True)[:15]  # Top 15 tags
        
        # Create bar chart
        fig = go.Figure()
        
        fig.add_trace(go.Bar(
            x=[tag[0] for tag in sorted_tags],
            y=[tag[1] for tag in sorted_tags],
            marker_color='#9b59b6',
            opacity=0.8
        ))
        
        fig.update_layout(
            title='Most Common Tags',
            xaxis_title='Tag',
            yaxis_title='Frequency',
            margin=dict(l=50, r=50, t=80, b=50)
        )
        
        # Convert to HTML
        chart_js = f"""
        <script>
            var tags_data = {pio.to_json(fig)};
            Plotly.newPlot('tags_chart', tags_data.data, tags_data.layout);
        </script>
        """
        
        return chart_js
    
    def generate_report(self, results, output_file):
        """Generate HTML report with interactive charts"""
        # Generate charts
        detection_chart_js = self.create_detection_chart(results)
        distribution_chart_js = self.create_distribution_chart(results)
        tags_chart_js = self.create_tags_chart(results)
        
        # Calculate summary statistics
        total_hashes = len(results)
        vx_found = sum(1 for details in results.values() if 'Found in VX database' in details['status'])
        vx_not_found = total_hashes - vx_found
        with_vt_data = sum(1 for details in results.values() if 'vt_data' in details and details['vt_data'] and 'error' not in details['vt_data'])
        
        # Get most common tags for template conditionals
        most_common_tags = []
        all_tags = {}
        for _, details in results.items():
            if 'vt_data' in details and details['vt_data'] and 'tags' in details['vt_data']:
                for tag in details['vt_data']['tags']:
                    all_tags[tag] = all_tags.get(tag, 0) + 1
        
        if all_tags:
            most_common_tags = sorted(all_tags.items(), key=lambda x: x[1], reverse=True)[:15]
        
        # Render template
        html_content = self.template.render(
            results=results,
            total_hashes=total_hashes,
            vx_found=vx_found,
            vx_not_found=vx_not_found,
            with_vt_data=with_vt_data,
            most_common_tags=most_common_tags,
            timestamp=datetime.now().strftime('%Y-%m-%d'),  # Changed to YYYY-MM-DD format
            current_year=datetime.now().year,
            detection_chart_js=detection_chart_js,
            distribution_chart_js=distribution_chart_js,
            tags_chart_js=tags_chart_js
        )
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file


# Function to use from main application
def generate_html_report(results, output_file):
    """Generate an HTML report with interactive charts from results"""
    reporter = HTMLReporter()
    return reporter.generate_report(results, output_file)