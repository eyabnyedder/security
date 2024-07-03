import re
import ipaddress
from odoo import models, fields, api
from odoo.exceptions import ValidationError

class ScanConfig(models.Model):
    _name = 'scan.config'
    _description = 'Menu de configuration des scans'

    name = fields.Char(string="Name", required=True)
    network_ip = fields.Char(string="Network / device IP(s)", required=True)
    excluded_ips = fields.Char(string="Excluded IPs")
    port = fields.Char(string="Port(s)")
    is_scheduled = fields.Boolean(string="Use for Scheduled Scans", default=False)

    @api.constrains('network_ip', 'excluded_ips')
    def _check_ips(self):
        def validate_ip(ip):
            if '-' in ip:
                start_ip, end_ip = ip.split('-')
                try:
                    ipaddress.ip_address(start_ip)
                    ipaddress.ip_address(end_ip)
                except ValueError:
                    raise ValidationError("Invalid IP range: %s" % ip)
            else:
                try:
                    if '/' in ip:
                        ipaddress.ip_network(ip, strict=False)
                    else:
                        ipaddress.ip_address(ip)
                except ValueError:
                    raise ValidationError("Invalid IP address or network: %s" % ip)

        def ip_in_network(ip, networks):
            ip_obj = ipaddress.ip_address(ip)
            for network in networks:
                if ip_obj in network:
                    return True
            return False

        def parse_ip_list(ip_list_str):
            ip_list = []
            ips = ip_list_str.split(',')
            for ip in ips:
                if '-' in ip:
                    start_ip, end_ip = ip.split('-')
                    ip_range = ipaddress.summarize_address_range(ipaddress.ip_address(start_ip),
                                                                 ipaddress.ip_address(end_ip))
                    for ip_net in ip_range:
                        ip_list.extend(ip_net.hosts())
                else:
                    ip_list.append(ipaddress.ip_address(ip))
            return ip_list

        def is_private_ip(ip):
            return ip.is_private

        for record in self:
            network_ips = []
            individual_ips = []
            if record.network_ip:
                network_ips = record.network_ip.split(',')
                network_objs = []
                for ip in network_ips:
                    validate_ip(ip)
                    if '/' in ip:
                        network_objs.append(ipaddress.ip_network(ip, strict=False))
                    elif '-' in ip:
                        start_ip, end_ip = ip.split('-')
                        ip_range = ipaddress.summarize_address_range(ipaddress.ip_address(start_ip),
                                                                     ipaddress.ip_address(end_ip))
                        for ip_net in ip_range:
                            network_objs.append(ip_net)
                    else:
                        individual_ips.append(ipaddress.ip_address(ip))
                    # Check if IPs are private
                    for ip_str in network_ips:
                        ip = ipaddress.ip_network(ip_str, strict=False) if '/' in ip_str else ipaddress.ip_address(
                            ip_str)
                        if not all(is_private_ip(ip) for ip in
                                   (ip.hosts() if isinstance(ip, ipaddress.IPv4Network) else [ip])):
                            raise ValidationError("Network IP address %s must be a private IP address." % ip_str)

            if record.excluded_ips:
                excluded_ips = parse_ip_list(record.excluded_ips)
                for ip in excluded_ips:
                    if ip in individual_ips:
                        raise ValidationError(
                            "Excluded IP address %s cannot be the same as the network / device IPs." % ip)
                    if any(ip == ind_ip for ind_ip in individual_ips):
                        raise ValidationError(
                            "Excluded IP address %s cannot be the same as the network / device IPs." % ip)
                    # Check if excluded IPs are private
                    if not is_private_ip(ip):
                        raise ValidationError("Excluded IP address %s must be a private IP address." % ip)

    @api.constrains('port')
    def _check_port(self):
        port_pattern = re.compile(r'^(\d{1,5})(,\d{1,5})*(\-(\d{1,5}))?$')

        for record in self:
            if record.port:
                ports = record.port.split(',')
                for port in ports:
                    if '-' in port:
                        start_port, end_port = port.split('-')
                        if not (start_port.isdigit() and end_port.isdigit() and 0 <= int(
                                start_port) <= 65535 and 0 <= int(end_port) <= 65535 and int(start_port) <= int(end_port)):
                            raise ValidationError("Invalid port interval: %s" % port)
                    elif not (port.isdigit() and 0 <= int(port) <= 65535):
                        raise ValidationError("Invalid port number: %s" % port)