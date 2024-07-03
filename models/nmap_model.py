import requests
import os
import re
import socket
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from bs4 import BeautifulSoup
from odoo import models, fields, api

from odoo17.odoo.exceptions import ValidationError


# Function to scrape description from NVD
def scrape_nvd_cve_description(cve_id):
    url = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        description_section = soup.find('p', {'data-testid': 'vuln-description'})
        if description_section:
            return description_section.get_text(strip=True)
        return 'No description available'
    else:
        return 'No description available'

# Function to scrape references from NVD
def scrape_nvd_cve_references(cve_id):
    url = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        references_section = soup.find('div', {'id': 'vulnHyperlinksPanel'})
        references = []
        if references_section:
            for ref in references_section.find_all('a'):
                href = ref.get('href', '').strip()
                text = ref.get_text(strip=True)
                references.append(f"{text}: {href}")
        else:
            return 'No references available'
        return '\n'.join(references) if references else 'No references available'
    else:
        return 'No references available'

# Function to map severity level
def map_severity_level(score):
    try:
        score = float(score)
        if score >= 7.0:
            return 'HIGH'
        elif 4.0 <= score < 7.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    except ValueError:
        return 'no_severity'

class NmapScan(models.Model):
    _name = 'nmap.scan'
    _description = 'Nmap Scan'

    name = fields.Char(string="Name", default="Scan")
    target_ips = fields.Char(string="Target IPs", default=lambda self: self._get_default_target_ips(), required=True)
    start_time = fields.Datetime(string="Start Time")
    end_time = fields.Datetime(string="End Time")
    status = fields.Selection([
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('done', 'Done'),
        ('failed', 'Failed')
    ], string="Status", default='pending')
    scan_results = fields.One2many('nmap.result', 'scan_id', string='Scan Results')
    excluded_ips = fields.Char(string="Excluded IPs")
    port = fields.Char(string="Port")

    def _get_default_target_ips(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            ip_address = sock.getsockname()[0]
            sock.close()
            return f"{ip_address}/24"
        except Exception as e:
            return "192.168.196.0/24"

    def start_scan(self):
        self.ensure_one()
        self.write({
            'status': 'running',
            'start_time': fields.Datetime.now()
        })

        start_time_str = self.start_time.strftime("%Y-%m-%d_%H-%M-%S")
        self.write({
            'name': f"Scan_{start_time_str}"
        })

        results_dir = '/home/eya/Bureau'
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)
        start_time_str = self.start_time.strftime("%Y-%m-%d_%H-%M-%S")
        results_file = os.path.join(results_dir, f"scan_{start_time_str}.xml")

        scan_command = ['nmap', '--script', 'nmap-vulners', '-sV', self.target_ips, '-oX', results_file]

        if self.excluded_ips:
            scan_command.extend(['--exclude', self.excluded_ips])

        if self.port:
            scan_command.extend(['-p', self.port])

        try:
            print(f"Running command: {' '.join(scan_command)}")
            subprocess.run(scan_command, check=True)

            with open(results_file, 'r') as file:
                scan_data = file.read()

            parsed_results = self.parse_scan_results(scan_data)

            self.write({
                'status': 'done',
                'end_time': fields.Datetime.now()
            })

            result_records = []
            for result in parsed_results:
                cve_records = [(0, 0, cve) for cve in result['cves']]
                result_records.append((0, 0, {
                    'host': result['host'],
                    'port': result['port'],
                    'service': result['service'],
                    'state': result['state'],
                    'version': result['version'],
                    'cves': cve_records
                }))
            self.write({'scan_results': result_records})
            print("cve info: ", result_records)

            return {"status": "success", "message": "Scan completed successfully"}
        except Exception as e:
            self.write({
                'status': 'failed'
            })
            print(f"Scan failed with error: {e}")  # Debug: Print the error
            return {"status": "error", "message": str(e)}


    def parse_scan_results(self, scan_data):
        root = ET.fromstring(scan_data)
        results = []

        for host in root.findall('host'):
            address = host.find('address').get('addr')
            for port in host.findall('ports/port'):
                port_id = port.get('portid')
                service_elem = port.find('service')
                service = service_elem.get('name', '') if service_elem is not None else ''
                state = port.find('state').get('state') if port.find('state') is not None else ''
                service_product = service_elem.get('product', '') if service_elem is not None else ''
                service_version = service_elem.get('version', '') if service_elem is not None else ''
                service_extrainfo = service_elem.get('extrainfo', '') if service_elem is not None else ''

                full_version = ' '.join(filter(None, [service_product, service_version, service_extrainfo]))

                # Initialize CVE list
                cve_list = []

                # Retrieve CVE information if available
                script_elem = port.find("./script[@id='vulners']")
                if script_elem is not None:
                    script_output = script_elem.get('output', '')
                    print(f"Script output for port {port_id}: {script_output}")  # Debug: Print the script output
                    cve_list = self.extract_cves_from_output(script_output)

                results.append({
                    'host': address,
                    'port': port_id,
                    'service': service,
                    'state': state,
                    'version': full_version,
                    'cves': cve_list
                })

        print("Parsed results:", results)
        return results

    def extract_cves_from_output(self, output):

        cve_list = []

        lines = output.split('\n')
        cve_id_pattern = re.compile(r'\bCVE-\d{4}-\d{4,7}\b')
        severity_pattern = re.compile(r'(\b\d+\.\d+\b)')

        for line in lines:
            if 'CVE-' in line:
                try:
                    cve_id_match = cve_id_pattern.search(line)
                    cve_id = cve_id_match.group(0) if cve_id_match else 'No CVE ID'

                    severity_match = severity_pattern.search(line)
                    severity_score = severity_match.group(0) if severity_match else 'No severity information available'
                    severity_level = map_severity_level(severity_score)

                    description = scrape_nvd_cve_description(cve_id)
                    references = scrape_nvd_cve_references(cve_id)


                    cve_list.append({
                        'cve_id': cve_id,
                        'description': description,
                        'severity_level': severity_level,
                        'references': references
                    })

                except Exception as e:
                    print(f"Error processing line: {line}")  # Debug: Print the line that caused an error
                    print(f"Error: {e}")  # Debug: Print the error message

        print(f"Extracted CVEs: {cve_list}")  # Debug: Print the extracted CVE list
        return cve_list

class NmapScanResult(models.Model):
    _name = 'nmap.result'
    _description = 'Nmap Scan Result'

    scan_id = fields.Many2one('nmap.scan', string='Scan Reference', required=True, ondelete='cascade')
    host = fields.Char(string='Host')
    port = fields.Char(string='Port')
    service = fields.Char(string='Service')
    version = fields.Char(string='Service Version')
    state = fields.Char(string='State')
    cves = fields.One2many('nmap.cve', 'result_id', string='CVEs')

class NmapCVE(models.Model):
    _name = 'nmap.cve'
    _description = 'Nmap CVE Information'

    result_id = fields.Many2one('nmap.result', string='Scan Result', required=True, ondelete='cascade')
    cve_id = fields.Char(string='CVE ID')
    description = fields.Text(string='Description')
    severity_level = fields.Selection([
        ('LOW', 'LOW'),
        ('MEDIUM', 'MEDIUM'),
        ('HIGH', 'HIGH'),
        ('no_severity', 'No severity information available')
    ], string="Severity Level", default='no_severity')
    references = fields.Text(string='References to Solutions and Tools')