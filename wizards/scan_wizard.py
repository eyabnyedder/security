# nsm_plus/wizards/scan_wizard.py
from odoo import models, fields, api

class ScanWizard(models.TransientModel):
    _name = 'scan.wizard'
    _description = 'Scan Wizard'

    # name = fields.Char(string="Name", required=True)
    scan_config_id = fields.Many2one('scan.config', string='Scan Configuration', required=True)

    def start_scan(self):
        scan_config = self.scan_config_id
        scan = self.env['nmap.scan'].create({
            # 'name': self.name,
            'target_ips': scan_config.network_ip,
            'excluded_ips': scan_config.excluded_ips,
            'port': scan_config.port,
        })
        scan.start_scan()
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'nmap.scan',
            'view_mode': 'form',
            'res_id': scan.id,
            'target': 'current',
        }