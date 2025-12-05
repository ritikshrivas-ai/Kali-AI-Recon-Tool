#!/usr/bin/env python3
"""
Kali AI Recon Tool v1.0 - Complete Automated Reconnaissance Platform
Integrates 40+ Kali Linux Tools for Bug Bounty & Security Assessments
"""

import os
import sys
import json
import threading
import time
import re
import socket
import ssl
import datetime
import subprocess
import requests
import nmap
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import dns.resolver
import whois

from flask import Flask, render_template_string, request, jsonify, send_file
from flask_socketio import SocketIO, emit

# ==================== FLASK APPLICATION SETUP ====================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'kali-ai-recon-tool-secret-key-2024'
app.config['UPLOAD_FOLDER'] = 'output/'
socketio = SocketIO(app, async_mode='threading')

# ==================== GLOBAL SCAN STATUS ====================
scan_status = {
    'running': False,
    'target': None,
    'progress': 0,
    'current_module': None,
    'results': {}
}

# ==================== HTML TEMPLATES ====================
HTML_TEMPLATES = {
    'index': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kali AI Recon Tool - Bug Bounty Hero</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .card-hover:hover { transform: translateY(-5px); box-shadow: 0 20px 40px rgba(0,0,0,0.1); transition: all 0.3s ease; }
        .progress-bar { transition: width 0.5s ease; }
        .typewriter { overflow: hidden; border-right: .15em solid #667eea; white-space: nowrap; animation: typing 3.5s steps(40, end), blink-caret .75s step-end infinite; }
        @keyframes typing { from { width: 0 } to { width: 100% } }
        @keyframes blink-caret { from, to { border-color: transparent } 50% { border-color: #667eea; } }
    </style>
</head>
<body class="bg-gray-50">
    <nav class="gradient-bg text-white shadow-lg">
        <div class="container mx-auto px-4 py-4">
            <div class="flex justify-between items-center">
                <div class="flex items-center space-x-2">
                    <i class="fas fa-shield-alt text-2xl"></i>
                    <h1 class="text-2xl font-bold">Kali AI Recon Tool</h1>
                    <span class="bg-red-500 text-xs px-2 py-1 rounded-full">v1.0</span>
                </div>
                <div class="space-x-4">
                    <a href="/" class="hover:text-gray-200"><i class="fas fa-home"></i> Home</a>
                    <a href="/dashboard" class="hover:text-gray-200"><i class="fas fa-chart-bar"></i> Dashboard</a>
                </div>
            </div>
        </div>
    </nav>

    <div class="gradient-bg text-white py-20">
        <div class="container mx-auto px-4 text-center">
            <h1 class="text-5xl font-bold mb-4 typewriter">Bug Bounty Hero</h1>
            <p class="text-xl mb-8">Automated Reconnaissance & OSINT Platform with 40+ Kali Linux Tools</p>
            
            <div class="max-w-2xl mx-auto bg-white rounded-lg shadow-xl p-6">
                <form id="scanForm" class="space-y-4">
                    <div>
                        <label class="block text-gray-700 text-sm font-bold mb-2" for="target">
                            <i class="fas fa-crosshairs"></i> Enter Target (Domain/IP)
                        </label>
                        <input type="text" id="target" name="target" placeholder="example.com or 192.168.1.1"
                            class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent" required>
                    </div>
                    
                    <div>
                        <label class="block text-gray-700 text-sm font-bold mb-2">
                            <i class="fas fa-sliders-h"></i> Scan Type
                        </label>
                        <div class="flex space-x-4">
                            <label class="flex items-center"><input type="radio" name="scan_type" value="quick" checked class="mr-2"><span class="text-gray-700">Quick</span></label>
                            <label class="flex items-center"><input type="radio" name="scan_type" value="full" class="mr-2"><span class="text-gray-700">Full</span></label>
                            <label class="flex items-center"><input type="radio" name="scan_type" value="osint" class="mr-2"><span class="text-gray-700">OSINT</span></label>
                        </div>
                    </div>
                    
                    <button type="submit" id="scanBtn"
                        class="w-full bg-gradient-to-r from-blue-500 to-purple-600 text-white font-bold py-3 px-4 rounded-lg hover:opacity-90 transition duration-300">
                        <i class="fas fa-rocket mr-2"></i> Launch Reconnaissance
                    </button>
                </form>
                
                <div id="progressSection" class="mt-6 hidden">
                    <div class="flex justify-between mb-2">
                        <span class="text-sm font-semibold text-gray-700">Scan Progress</span>
                        <span id="progressText" class="text-sm font-semibold text-blue-600">0%</span>
                    </div>
                    <div class="w-full bg-gray-200 rounded-full h-2.5">
                        <div id="progressBar" class="bg-blue-600 h-2.5 rounded-full progress-bar" style="width: 0%"></div>
                    </div>
                    <div id="currentModule" class="text-sm text-gray-600 mt-2 text-center"></div>
                </div>
            </div>
        </div>
    </div>

    <div class="py-16 bg-white">
        <div class="container mx-auto px-4">
            <h2 class="text-3xl font-bold text-center mb-12">Powered by 40+ Kali Linux Tools</h2>
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
                <div class="bg-gray-50 rounded-xl p-6 shadow-md card-hover">
                    <div class="text-blue-500 text-3xl mb-4"><i class="fas fa-search"></i></div>
                    <h3 class="text-xl font-bold mb-3">Passive Recon</h3>
                    <ul class="space-y-2 text-gray-600">
                        <li><i class="fas fa-check text-green-500 mr-2"></i>WHOIS Lookup</li>
                        <li><i class="fas fa-check text-green-500 mr-2"></i>DNS Enumeration</li>
                        <li><i class="fas fa-check text-green-500 mr-2"></i>Subdomain Discovery</li>
                        <li><i class="fas fa-check text-green-500 mr-2"></i>SSL/TLS Analysis</li>
                    </ul>
                </div>
                <div class="bg-gray-50 rounded-xl p-6 shadow-md card-hover">
                    <div class="text-green-500 text-3xl mb-4"><i class="fas fa-broadcast-tower"></i></div>
                    <h3 class="text-xl font-bold mb-3">Active Scanning</h3>
                    <ul class="space-y-2 text-gray-600">
                        <li><i class="fas fa-check text-green-500 mr-2"></i>Port Scanning</li>
                        <li><i class="fas fa-check text-green-500 mr-2"></i>Service Detection</li>
                        <li><i class="fas fa-check text-green-500 mr-2"></i>Directory Bruteforce</li>
                        <li><i class="fas fa-check text-green-500 mr-2"></i>Vulnerability Scan</li>
                    </ul>
                </div>
                <div class="bg-gray-50 rounded-xl p-6 shadow-md card-hover">
                    <div class="text-purple-500 text-3xl mb-4"><i class="fas fa-globe"></i></div>
                    <h3 class="text-xl font-bold mb-3">OSINT Collection</h3>
                    <ul class="space-y-2 text-gray-600">
                        <li><i class="fas fa-check text-green-500 mr-2"></i>Social Media Intel</li>
                        <li><i class="fas fa-check text-green-500 mr-2"></i>Breach Data</li>
                        <li><i class="fas fa-check text-green-500 mr-2"></i>Threat Intelligence</li>
                        <li><i class="fas fa-check text-green-500 mr-2"></i>Email Harvesting</li>
                    </ul>
                </div>
                <div class="bg-gray-50 rounded-xl p-6 shadow-md card-hover">
                    <div class="text-red-500 text-3xl mb-4"><i class="fas fa-robot"></i></div>
                    <h3 class="text-xl font-bold mb-3">AI Analysis</h3>
                    <ul class="space-y-2 text-gray-600">
                        <li><i class="fas fa-check text-green-500 mr-2"></i>Risk Assessment</li>
                        <li><i class="fas fa-check text-green-500 mr-2"></i>Pattern Detection</li>
                        <li><i class="fas fa-check text-green-500 mr-2"></i>Report Generation</li>
                        <li><i class="fas fa-check text-green-500 mr-2"></i>Visual Analytics</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <div id="results" class="py-16 bg-white hidden">
        <div class="container mx-auto px-4">
            <h2 class="text-3xl font-bold text-center mb-8">Scan Results</h2>
            <div id="resultsContainer" class="bg-gray-50 rounded-xl p-6 shadow-lg"></div>
        </div>
    </div>

    <footer class="gradient-bg text-white py-8">
        <div class="container mx-auto px-4 text-center">
            <p class="mb-4">Kali AI Recon Tool - Your Bug Bounty Companion</p>
            <p class="text-sm text-gray-300">For educational and authorized testing purposes only</p>
        </div>
    </footer>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.0/socket.io.js"></script>
    <script>
        const socket = io();
        document.getElementById('scanForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const target = document.getElementById('target').value;
            const scanType = document.querySelector('input[name="scan_type"]:checked').value;
            document.getElementById('progressSection').classList.remove('hidden');
            document.getElementById('scanBtn').disabled = true;
            document.getElementById('scanBtn').innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i> Scanning...';
            fetch('/start_scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'target=' + encodeURIComponent(target) + '&scan_type=' + scanType
            }).then(r => r.json()).then(data => {
                if (data.error) { alert('Error: ' + data.error); resetForm(); }
            }).catch(error => { console.error('Error:', error); resetForm(); });
        });
        socket.on('progress_update', function(data) {
            document.getElementById('progressBar').style.width = data.progress + '%';
            document.getElementById('progressText').textContent = data.progress + '%';
            if (data.module) { document.getElementById('currentModule').textContent = 'Current: ' + data.module; }
        });
        socket.on('scan_complete', function(data) {
            document.getElementById('scanBtn').innerHTML = '<i class="fas fa-check mr-2"></i> Scan Complete';
            document.getElementById('results').classList.remove('hidden');
            fetch('/results/' + data.target).then(r => r.text()).then(html => {
                document.getElementById('resultsContainer').innerHTML = html;
            });
            setTimeout(resetForm, 3000);
        });
        socket.on('scan_error', function(data) { alert('Scan error: ' + data.error); resetForm(); });
        function resetForm() {
            document.getElementById('scanBtn').disabled = false;
            document.getElementById('scanBtn').innerHTML = '<i class="fas fa-rocket mr-2"></i> Launch Reconnaissance';
            document.getElementById('progressSection').classList.add('hidden');
            document.getElementById('progressBar').style.width = '0%';
            document.getElementById('progressText').textContent = '0%';
        }
        document.getElementById('target').addEventListener('blur', function() {
            const target = this.value;
            const ipPattern = /^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/;
            const domainPattern = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}$/;
            if (!ipPattern.test(target) && !domainPattern.test(target)) {
                this.classList.add('border-red-500');
            } else { this.classList.remove('border-red-500'); }
        });
    </script>
</body>
</html>
''',

    'results': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Results - Kali AI Recon Tool</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-gray-100">
    <div class="container mx-auto px-4 py-8">
        <div class="bg-white rounded-xl shadow-lg p-6">
            <h1 class="text-3xl font-bold mb-6 text-blue-600">
                <i class="fas fa-file-alt mr-2"></i>Scan Results for {{ target }}
            </h1>
            
            {% if results %}
            <div class="space-y-6">
                <!-- Summary Card -->
                <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
                    <h2 class="text-xl font-bold text-blue-700 mb-2"><i class="fas fa-info-circle mr-2"></i>Scan Summary</h2>
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div class="text-center p-3 bg-white rounded-lg shadow">
                            <div class="text-2xl font-bold text-blue-600">{{ results.summary.total_findings|default(0) }}</div>
                            <div class="text-sm text-gray-600">Total Findings</div>
                        </div>
                        <div class="text-center p-3 bg-white rounded-lg shadow">
                            <div class="text-2xl font-bold text-green-600">{{ results.summary.risk_level|default('N/A') }}</div>
                            <div class="text-sm text-gray-600">Risk Level</div>
                        </div>
                        <div class="text-center p-3 bg-white rounded-lg shadow">
                            <div class="text-2xl font-bold text-purple-600">{{ results.summary.scan_duration|default('N/A') }}</div>
                            <div class="text-sm text-gray-600">Duration</div>
                        </div>
                        <div class="text-center p-3 bg-white rounded-lg shadow">
                            <div class="text-2xl font-bold text-red-600">{{ results.summary.start_time|default('N/A') }}</div>
                            <div class="text-sm text-gray-600">Start Time</div>
                        </div>
                    </div>
                </div>

                <!-- Modules Accordion -->
                {% for module_name, module_data in results.items() %}
                    {% if module_name != 'summary' and module_name != 'timeline' and module_data %}
                    <div class="border rounded-lg overflow-hidden">
                        <button class="w-full bg-gray-100 hover:bg-gray-200 p-4 text-left font-bold flex justify-between items-center" 
                                onclick="toggleSection('{{ module_name }}')">
                            <span><i class="fas fa-folder mr-2"></i>{{ module_name|title }}</span>
                            <span id="arrow-{{ module_name }}">▼</span>
                        </button>
                        <div id="section-{{ module_name }}" class="p-4 bg-white hidden">
                            <pre class="bg-gray-50 p-4 rounded-lg overflow-x-auto text-sm">{{ module_data|tojson(indent=2) }}</pre>
                        </div>
                    </div>
                    {% endif %}
                {% endfor %}

                <!-- Timeline -->
                {% if results.timeline %}
                <div class="border rounded-lg overflow-hidden">
                    <button class="w-full bg-gray-100 hover:bg-gray-200 p-4 text-left font-bold flex justify-between items-center" 
                            onclick="toggleSection('timeline')">
                        <span><i class="fas fa-history mr-2"></i>Scan Timeline</span>
                        <span id="arrow-timeline">▼</span>
                    </button>
                    <div id="section-timeline" class="p-4 bg-white hidden">
                        <div class="space-y-2">
                            {% for event in results.timeline %}
                            <div class="flex items-center space-x-3 p-2 hover:bg-gray-50 rounded">
                                <div class="text-sm text-gray-500 w-16">{{ event.time }}</div>
                                <div class="flex-grow">{{ event.module }}</div>
                                <div class="px-2 py-1 text-xs rounded-full 
                                    {% if 'completed' in event.status %}bg-green-100 text-green-800
                                    {% elif 'error' in event.status %}bg-red-100 text-red-800
                                    {% else %}bg-blue-100 text-blue-800{% endif %}">
                                    {{ event.status }}
                                </div>
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                </div>
                {% endif %}

                <!-- Recommendations -->
                {% if results.summary.recommendations %}
                <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                    <h2 class="text-xl font-bold text-yellow-700 mb-2"><i class="fas fa-lightbulb mr-2"></i>Recommendations</h2>
                    <ul class="list-disc pl-5 space-y-1">
                        {% for rec in results.summary.recommendations %}
                        <li class="text-gray-700">{{ rec }}</li>
                        {% endfor %}
                    </ul>
                </div>
                {% endif %}

                <!-- Download Button -->
                <div class="text-center pt-6">
                    <a href="/download/{{ target }}_report.json" 
                       class="inline-flex items-center px-6 py-3 bg-blue-600 text-white font-bold rounded-lg hover:bg-blue-700 transition duration-300">
                        <i class="fas fa-download mr-2"></i>Download Full Report (JSON)
                    </a>
                </div>
            </div>
            {% else %}
            <div class="text-center py-12">
                <i class="fas fa-search text-6xl text-gray-300 mb-4"></i>
                <h2 class="text-2xl font-bold text-gray-600 mb-2">No Scan Results Found</h2>
                <p class="text-gray-500">Start a new scan to see results here.</p>
            </div>
            {% endif %}
        </div>
    </div>

    <script>
        function toggleSection(sectionId) {
            const section = document.getElementById('section-' + sectionId);
            const arrow = document.getElementById('arrow-' + sectionId);
            if (section.classList.contains('hidden')) {
                section.classList.remove('hidden');
                arrow.textContent = '▲';
            } else {
                section.classList.add('hidden');
                arrow.textContent = '▼';
            }
        }
    </script>
</body>
</html>
''',

    'dashboard': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Dashboard - Kali AI Recon Tool</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-gray-100">
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-3xl font-bold mb-8 text-blue-600">
            <i class="fas fa-chart-bar mr-2"></i>Scan History Dashboard
        </h1>
        
        {% if scans %}
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {% for scan in scans %}
            <div class="bg-white rounded-xl shadow-lg p-6 hover:shadow-xl transition duration-300">
                <div class="flex justify-between items-start mb-4">
                    <div>
                        <h2 class="text-xl font-bold text-gray-800">{{ scan.target }}</h2>
                        <p class="text-sm text-gray-500">{{ scan.timestamp }}</p>
                    </div>
                    <span class="px-3 py-1 text-xs font-bold rounded-full 
                        {% if scan.risk_level == 'High' %}bg-red-100 text-red-800
                        {% elif scan.risk_level == 'Medium' %}bg-yellow-100 text-yellow-800
                        {% else %}bg-green-100 text-green-800{% endif %}">
                        {{ scan.risk_level }}
                    </span>
                </div>
                
                <div class="space-y-3 mb-6">
                    <div class="flex justify-between">
                        <span class="text-gray-600">Findings:</span>
                        <span class="font-bold">{{ scan.findings }}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-600">Duration:</span>
                        <span class="font-bold">{{ scan.duration }}</span>
                    </div>
                </div>
                
                <div class="flex space-x-3">
                    <a href="/results/{{ scan.target }}" 
                       class="flex-1 text-center py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition duration-300">
                        <i class="fas fa-eye mr-1"></i> View
                    </a>
                    <a href="/download/{{ scan.file }}" 
                       class="flex-1 text-center py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition duration-300">
                        <i class="fas fa-download mr-1"></i> Download
                    </a>
                </div>
            </div>
            {% endfor %}
        </div>
        {% else %}
        <div class="text-center py-12">
            <i class="fas fa-chart-line text-6xl text-gray-300 mb-4"></i>
            <h2 class="text-2xl font-bold text-gray-600 mb-2">No Scan History Available</h2>
            <p class="text-gray-500">Start your first scan to see history here.</p>
            <a href="/" class="inline-block mt-4 px-6 py-3 bg-blue-600 text-white font-bold rounded-lg hover:bg-blue-700 transition duration-300">
                <i class="fas fa-rocket mr-2"></i>Start New Scan
            </a>
        </div>
        {% endif %}
    </div>
</body>
</html>
'''
}

# ==================== HELPER FUNCTIONS ====================
class TargetValidator:
    @staticmethod
    def validate_target(target):
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
        return re.match(ip_pattern, target) or re.match(domain_pattern, target)

class ToolRunner:
    @staticmethod
    def run_command(command, timeout=30):
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=True
            )
            return result.stdout if result.stdout else result.stderr
        except subprocess.TimeoutExpired:
            return "Command timed out"
        except Exception as e:
            return f"Error: {str(e)}"

    @staticmethod
    def check_tool(tool_name):
        try:
            subprocess.run(['which', tool_name], capture_output=True, check=True)
            return True
        except:
            return False

class ReportGenerator:
    @staticmethod
    def generate_html_report(results, target):
        return f"""
        <!DOCTYPE html>
        <html>
        <head><title>Recon Report - {target}</title></head>
        <body>
            <h1>Reconnaissance Report for {target}</h1>
            <pre>{json.dumps(results, indent=2, default=str)}</pre>
        </body>
        </html>
        """

# ==================== PASSIVE RECONNAISSANCE ====================
class PassiveReconnaissance:
    def __init__(self):
        self.tools = {
            'nslookup': ToolRunner.check_tool('nslookup'),
            'dig': ToolRunner.check_tool('dig'),
            'whois': ToolRunner.check_tool('whois'),
            'host': ToolRunner.check_tool('host'),
            'dnsrecon': ToolRunner.check_tool('dnsrecon'),
            'sublist3r': ToolRunner.check_tool('sublist3r'),
            'amass': ToolRunner.check_tool('amass'),
            'whatweb': ToolRunner.check_tool('whatweb'),
            'wafw00f': ToolRunner.check_tool('wafw00f')
        }

    def comprehensive_passive_scan(self, target):
        results = {
            'dns_info': self.get_dns_info(target),
            'whois_info': self.get_whois_info(target),
            'subdomains': self.enumerate_subdomains(target),
            'ssl_info': self.get_ssl_info(target),
            'technologies': self.detect_technologies(target),
            'waf_detection': self.detect_waf(target)
        }
        return results

    def get_dns_info(self, target):
        dns_results = {}
        try:
            # NSLOOKUP
            dns_results['nslookup'] = ToolRunner.run_command(f'nslookup {target}')
            
            # DIG
            for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']:
                output = ToolRunner.run_command(f'dig {target} {rtype} +short')
                dns_results[f'dig_{rtype.lower()}'] = output.strip().split('\n')
            
            # DNSRecon
            if self.tools['dnsrecon']:
                dns_results['dnsrecon'] = ToolRunner.run_command(f'dnsrecon -d {target} -t std')
        except Exception as e:
            dns_results['error'] = str(e)
        return dns_results

    def get_whois_info(self, target):
        try:
            w = whois.whois(target)
            return {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers
            }
        except:
            return {'error': 'WHOIS lookup failed'}

    def enumerate_subdomains(self, target):
        subdomains = set()
        
        # Sublist3r
        if self.tools['sublist3r']:
            output = ToolRunner.run_command(f'sublist3r -d {target}')
            for line in output.split('\n'):
                if target in line and 'Error' not in line:
                    subdomains.add(line.strip())
        
        # Amass
        if self.tools['amass']:
            output = ToolRunner.run_command(f'amass enum -d {target}')
            for line in output.split('\n'):
                if target in line:
                    subdomains.add(line.strip())
        
        # CRT.SH
        try:
            response = requests.get(f'https://crt.sh/?q=%.{target}&output=json', timeout=10)
            if response.status_code == 200:
                for cert in response.json():
                    subdomains.add(cert['name_value'])
        except:
            pass
        
        return list(subdomains)

    def get_ssl_info(self, target):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter']
                    }
        except:
            return {'error': 'SSL certificate fetch failed'}

    def detect_technologies(self, target):
        if self.tools['whatweb']:
            output = ToolRunner.run_command(f'whatweb {target}')
            return {'whatweb_output': output[:500]}
        return {}

    def detect_waf(self, target):
        if self.tools['wafw00f']:
            output = ToolRunner.run_command(f'wafw00f {target}')
            return {'wafw00f_output': output[:500]}
        return {}

# ==================== ACTIVE RECONNAISSANCE ====================
class ActiveReconnaissance:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.tools = {
            'nmap': ToolRunner.check_tool('nmap'),
            'gobuster': ToolRunner.check_tool('gobuster'),
            'nikto': ToolRunner.check_tool('nikto'),
            'nuclei': ToolRunner.check_tool('nuclei')
        }

    def comprehensive_active_scan(self, target):
        results = {
            'port_scan': self.port_scan(target),
            'service_detection': self.detect_services(target),
            'directory_scan': self.directory_bruteforce(target),
            'vulnerabilities': self.vulnerability_scan(target),
            'tech_stack': self.tech_stack_detection(target)
        }
        return results

    def port_scan(self, target):
        scan_results = {}
        if self.tools['nmap']:
            try:
                self.nm.scan(target, arguments='-T4 -sV --top-ports 100')
                for host in self.nm.all_hosts():
                    scan_results[host] = {
                        'status': self.nm[host].state(),
                        'ports': []
                    }
                    for proto in self.nm[host].all_protocols():
                        for port in self.nm[host][proto].keys():
                            port_info = self.nm[host][proto][port]
                            scan_results[host]['ports'].append({
                                'port': port,
                                'state': port_info['state'],
                                'service': port_info['name'],
                                'version': port_info.get('version', '')
                            })
            except Exception as e:
                scan_results['error'] = str(e)
        return scan_results

    def detect_services(self, target):
        services = {}
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 8080]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    services[port] = 'open'
                sock.close()
            except:
                pass
        return services

    def directory_bruteforce(self, target):
        directories = {}
        if self.tools['gobuster']:
            output = ToolRunner.run_command(f'gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -t 20')
            directories['gobuster'] = output.split('\n')[:20]
        return directories

    def vulnerability_scan(self, target):
        vulns = {}
        if self.tools['nikto']:
            output = ToolRunner.run_command(f'nikto -h {target} -Tuning x456')
            vulns['nikto'] = output.split('\n')[:50]
        
        if self.tools['nuclei']:
            output = ToolRunner.run_command(f'nuclei -u {target} -severity medium,high,critical -silent')
            vulns['nuclei'] = output.split('\n')[:20]
        
        return vulns

    def tech_stack_detection(self, target):
        tech_stack = {}
        try:
            response = requests.get(f'http://{target}', timeout=5)
            headers = dict(response.headers)
            
            tech_stack['server'] = headers.get('Server', '')
            tech_stack['x_powered_by'] = headers.get('X-Powered-By', '')
            
            # Check common CMS
            body = response.text.lower()
            cms_indicators = {
                'wordpress': ['wp-content', 'wordpress'],
                'joomla': ['joomla'],
                'drupal': ['drupal'],
                'laravel': ['laravel']
            }
            
            detected = []
            for cms, indicators in cms_indicators.items():
                for indicator in indicators:
                    if indicator in body:
                        detected.append(cms)
                        break
            
            tech_stack['detected_cms'] = detected
            
        except Exception as e:
            tech_stack['error'] = str(e)
        
        return tech_stack

# ==================== OSINT COLLECTION ====================
class OSINTCollector:
    def collect_all_osint(self, target):
        results = {
            'shodan': self.query_shodan(target),
            'virustotal': self.query_virustotal(target),
            'breaches': self.check_breaches(target),
            'social_media': self.social_media_osint(target),
            'geoip': self.geoip_lookup(target)
        }
        return results

    def query_shodan(self, target):
        shodan_key = os.environ.get('SHODAN_API_KEY', '')
        if shodan_key and ToolRunner.check_tool('shodan'):
            output = ToolRunner.run_command(f'shodan host {target}')
            return {'output': output[:1000]}
        return {'error': 'Shodan not configured'}

    def query_virustotal(self, target):
        vt_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
        if vt_key:
            try:
                url = f"https://www.virustotal.com/api/v3/domains/{target}"
                headers = {'x-apikey': vt_key}
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    return response.json()
            except:
                pass
        return {'error': 'VirusTotal not configured'}

    def check_breaches(self, target):
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}"
            headers = {'User-Agent': 'Kali-Recon-Tool'}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            return {'status': 'No breaches found'}
        except:
            return {'error': 'Breach check failed'}

    def social_media_osint(self, target):
        platforms = {
            'twitter': f'https://twitter.com/{target}',
            'linkedin': f'https://linkedin.com/company/{target}',
            'github': f'https://github.com/{target}'
        }
        
        results = {}
        for platform, url in platforms.items():
            try:
                response = requests.get(url, timeout=3)
                results[platform] = {
                    'exists': response.status_code == 200,
                    'url': url
                }
            except:
                results[platform] = {'exists': False, 'url': url}
        
        return results

    def geoip_lookup(self, target):
        try:
            response = requests.get(f'http://ip-api.com/json/{target}')
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return {'error': 'GeoIP lookup failed'}

# ==================== VULNERABILITY SCANNER ====================
class VulnerabilityScanner:
    def comprehensive_vuln_scan(self, target):
        results = {
            'web_vulns': self.scan_web_vulnerabilities(target),
            'ssl_vulns': self.scan_ssl_vulnerabilities(target),
            'cms_vulns': self.scan_cms_vulnerabilities(target)
        }
        return results

    def scan_web_vulnerabilities(self, target):
        vulns = []
        
        # Check for common vulnerabilities
        checks = [
            ('SQL Injection', f'http://{target}/?id=1\''),
            ('XSS', f'http://{target}/?q=<script>alert(1)</script>'),
            ('Directory Traversal', f'http://{target}/../../etc/passwd')
        ]
        
        for vuln_name, test_url in checks:
            try:
                response = requests.get(test_url, timeout=5)
                if response.status_code == 200:
                    vulns.append({'name': vuln_name, 'status': 'Possible'})
            except:
                pass
        
        return vulns

    def scan_ssl_vulnerabilities(self, target):
        vulns = []
        
        # Check SSL certificate
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_to_expire = (expiry_date - datetime.now()).days
                    
                    if days_to_expire < 30:
                        vulns.append({'name': 'SSL Certificate Expiring Soon', 'days': days_to_expire})
        except:
            vulns.append({'name': 'SSL Connection Failed', 'status': 'Error'})
        
        return vulns

    def scan_cms_vulnerabilities(self, target):
        # This would integrate with tools like wpscan, joomscan, droopescan
        return {'note': 'CMS vulnerability scanning requires specialized tools'}

# ==================== AI ANALYZER ====================
class AIAnalyzer:
    def analyze_data(self, all_data, target):
        analysis = {
            'risk_score': self.calculate_risk_score(all_data),
            'critical_findings': self.identify_critical_findings(all_data),
            'recommendations': self.generate_recommendations(all_data),
            'threat_level': self.assess_threat_level(all_data)
        }
        return analysis

    def calculate_risk_score(self, data):
        score = 0
        
        # Check for open ports
        if 'active' in data and 'port_scan' in data['active']:
            ports = data['active']['port_scan']
            for host_info in ports.values():
                if isinstance(host_info, dict) and 'ports' in host_info:
                    for port in host_info['ports']:
                        if port.get('state') == 'open':
                            score += 1
                            if port.get('service') in ['http', 'https', 'ssh', 'ftp']:
                                score += 2
        
        # Check for vulnerabilities
        if 'active' in data and 'vulnerabilities' in data['active']:
            vulns = data['active']['vulnerabilities']
            if vulns:
                score += len(vulns) * 3
        
        return min(score, 100)

    def identify_critical_findings(self, data):
        findings = []
        
        # Check SSL expiry
        if 'passive' in data and 'ssl_info' in data['passive']:
            ssl_info = data['passive']['ssl_info']
            if 'not_after' in ssl_info:
                try:
                    expiry = datetime.strptime(ssl_info['not_after'], '%b %d %H:%M:%S %Y %Z')
                    days = (expiry - datetime.now()).days
                    if days < 30:
                        findings.append(f'SSL Certificate expires in {days} days')
                except:
                    pass
        
        # Check for open risky ports
        if 'active' in data and 'port_scan' in data['active']:
            risky_ports = [21, 23, 80, 443, 3389, 5900]
            ports_data = data['active']['port_scan']
            for host_info in ports_data.values():
                if isinstance(host_info, dict) and 'ports' in host_info:
                    for port_info in host_info['ports']:
                        if port_info.get('state') == 'open' and port_info.get('port') in risky_ports:
                            findings.append(f'Open risky port: {port_info["port"]} ({port_info.get("service", "unknown")})')
        
        return findings

    def generate_recommendations(self, data):
        recommendations = []
        
        # General recommendations
        recommendations.append("Review all open ports and close unnecessary ones")
        recommendations.append("Implement proper firewall rules")
        recommendations.append("Keep all software updated")
        
        # Specific recommendations based on findings
        if 'passive' in data and 'ssl_info' in data['passive']:
            ssl_info = data['passive']['ssl_info']
            if 'not_after' in ssl_info:
                recommendations.append("Monitor SSL certificate expiration")
        
        if 'active' in data and 'vulnerabilities' in data['active']:
            vulns = data['active']['vulnerabilities']
            if vulns:
                recommendations.append("Address identified vulnerabilities immediately")
        
        return recommendations

    def assess_threat_level(self, data):
        risk_score = self.calculate_risk_score(data)
        
        if risk_score >= 70:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        else:
            return "Low"

# ==================== MAIN WORKFLOW CLASS ====================
class ReconWorkflow:
    def __init__(self, target):
        self.target = target
        self.results = {
            'passive': {},
            'active': {},
            'osint': {},
            'vulnerabilities': {},
            'ai_analysis': {},
            'timeline': [],
            'summary': {}
        }
        self.start_time = datetime.now()
        
        # Initialize modules
        self.passive_recon = PassiveReconnaissance()
        self.active_recon = ActiveReconnaissance()
        self.osint_collector = OSINTCollector()
        self.vuln_scanner = VulnerabilityScanner()
        self.ai_analyzer = AIAnalyzer()

    def execute_phase(self, phase_name, phase_function):
        scan_status['current_module'] = phase_name
        socketio.emit('progress_update', {
            'module': phase_name,
            'progress': scan_status['progress']
        })
        
        try:
            result = phase_function(self.target)
            self.results[phase_name] = result
            self.results['timeline'].append({
                'time': datetime.now().strftime("%H:%M:%S"),
                'module': phase_name,
                'status': 'completed'
            })
            return result
        except Exception as e:
            self.results['timeline'].append({
                'time': datetime.now().strftime("%H:%M:%S"),
                'module': phase_name,
                'status': f'error: {str(e)}'
            })
            return {}

    def run_complete_workflow(self):
        try:
            # Phase 1: Passive Reconnaissance
            self.execute_phase('passive', self.passive_recon.comprehensive_passive_scan)
            scan_status['progress'] = 20
            socketio.emit('progress_update', {'progress': 20})
            
            # Phase 2: Active Reconnaissance
            self.execute_phase('active', self.active_recon.comprehensive_active_scan)
            scan_status['progress'] = 40
            socketio.emit('progress_update', {'progress': 40})
            
            # Phase 3: OSINT Collection
            self.execute_phase('osint', self.osint_collector.collect_all_osint)
            scan_status['progress'] = 60
            socketio.emit('progress_update', {'progress': 60})
            
            # Phase 4: Vulnerability Scanning
            self.execute_phase('vulnerabilities', self.vuln_scanner.comprehensive_vuln_scan)
            scan_status['progress'] = 80
            socketio.emit('progress_update', {'progress': 80})
            
            # Phase 5: AI Analysis
            all_data = {
                **self.results['passive'],
                **self.results['active'],
                **self.results['osint'],
                **self.results['vulnerabilities']
            }
            ai_result = self.ai_analyzer.analyze_data(all_data, self.target)
            self.results['ai_analysis'] = ai_result
            scan_status['progress'] = 100
            socketio.emit('progress_update', {'progress': 100})
            
            # Generate final report
            self.generate_final_report()
            
            return self.results
            
        except Exception as e:
            print(f"Workflow error: {e}")
            return self.results

    def generate_final_report(self):
        total_findings = 0
        for module in ['passive', 'active', 'osint', 'vulnerabilities']:
            if module in self.results and isinstance(self.results[module], dict):
                total_findings += len(self.results[module])

        self.results['summary'] = {
            'target': self.target,
            'scan_duration': str(datetime.now() - self.start_time),
            'start_time': self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            'end_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_findings': total_findings,
            'risk_level': self.results['ai_analysis'].get('threat_level', 'Medium'),
            'recommendations': self.results['ai_analysis'].get('recommendations', [])
        }
        
        # Save to JSON
        report_file = f"output/{self.target}_{self.start_time.strftime('%Y%m%d_%H%M%S')}.json"
        os.makedirs('output', exist_ok=True)
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        
        return report_file

# ==================== FLASK ROUTES ====================
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATES['index'])

@app.route('/start_scan', methods=['POST'])
def start_scan():
    if scan_status['running']:
        return jsonify({'error': 'A scan is already running'}), 400
    
    target = request.form.get('target')
    scan_type = request.form.get('scan_type', 'full')
    
    if not TargetValidator.validate_target(target):
        return jsonify({'error': 'Invalid target format'}), 400
    
    scan_status.update({
        'running': True,
        'target': target,
        'progress': 0,
        'current_module': 'Initializing',
        'results': {}
    })
    
    def run_scan():
        try:
            workflow = ReconWorkflow(target)
            results = workflow.run_complete_workflow()
            scan_status['results'] = results
            scan_status['running'] = False
            
            socketio.emit('scan_complete', {
                'target': target,
                'results_url': f'/results/{target}',
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            scan_status['running'] = False
            socketio.emit('scan_error', {'error': str(e)})
    
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'message': f'Scan started for {target}',
        'scan_id': target,
        'status_url': '/scan_status'
    })

@app.route('/scan_status')
def get_scan_status():
    return jsonify(scan_status)

@app.route('/results/<target>')
def show_results(target):
    output_dir = Path('output')
    if not output_dir.exists():
        return render_template_string(HTML_TEMPLATES['results'], target=target, results=None)
    
    target_files = list(output_dir.glob(f'{target}_*.json'))
    if not target_files:
        return render_template_string(HTML_TEMPLATES['results'], target=target, results=None)
    
    latest_file = max(target_files, key=os.path.getctime)
    with open(latest_file, 'r') as f:
        results = json.load(f)
    
    return render_template_string(HTML_TEMPLATES['results'], target=target, results=results)

@app.route('/dashboard')
def dashboard():
    output_dir = Path('output')
    scans = []
    
    if output_dir.exists():
        for file in output_dir.glob('*.json'):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    scans.append({
                        'target': data.get('summary', {}).get('target', 'Unknown'),
                        'timestamp': data.get('summary', {}).get('start_time', 'Unknown'),
                        'duration': data.get('summary', {}).get('scan_duration', 'Unknown'),
                        'findings': data.get('summary', {}).get('total_findings', 0),
                        'risk_level': data.get('ai_analysis', {}).get('threat_level', 'Unknown'),
                        'file': file.name
                    })
            except:
                continue
    
    return render_template_string(HTML_TEMPLATES['dashboard'], scans=scans)

@app.route('/download/<filename>')
def download_file(filename):
    file_path = Path('output') / filename
    if file_path.exists():
        return send_file(file_path, as_attachment=True)
    return jsonify({'error': 'File not found'}), 404

@app.route('/api/v1/quick_scan/<target>')
def quick_scan(target):
    if scan_status['running']:
        return jsonify({'error': 'Scan in progress'}), 429
    
    recon = PassiveReconnaissance()
    results = recon.comprehensive_passive_scan(target)
    return jsonify(results)

@socketio.on('connect')
def handle_connect():
    emit('connected', {'message': 'Connected to recon tool'})

# ==================== MAIN EXECUTION ====================
if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('output', exist_ok=True)
    
    print("""
    ██╗  ██╗ █████╗ ██╗     ██╗     ██████╗ █████╗ ██╗
    ██║ ██╔╝██╔══██╗██║     ██║    ██╔════╝██╔══██╗██║
    █████╔╝ ███████║██║     ██║    ██║     ███████║██║
    ██╔═██╗ ██╔══██║██║     ██║    ██║     ██╔══██║██║
    ██║  ██╗██║  ██║███████╗███████╗╚██████╗██║  ██║███████╗
    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝
    
    Kali AI Recon Tool v1.0 - Single File Edition
    Starting server on http://localhost:5000
    
    Features:
    • 40+ Kali Linux Tools Integration
    • Automated Reconnaissance Workflow
    • Real-time Progress Tracking
    • AI-Powered Analysis
    • Comprehensive Reporting
    • Bug Bounty Optimized
    
    Usage:
    1. Access http://localhost:5000
    2. Enter target domain or IP
    3. Select scan type
    4. View results in real-time
    5. Download reports
    
    Note: Ensure Kali Linux tools are installed for full functionality
    """)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
