{
    'name': 'Vulnerability Scanner',
    'version': '1.0',
    'summary': 'Vulnerability Scanner',
    'sequence': 1,
    'depends': ['base'],
    'installable': True,
    'auto_install': True,
    'data': [
        "security/ir.model.access.csv",
        "views/nmap_scan_results.xml",
        "views/report_nmap_scan.xml",
        "report/nmap_scan_report.xml",
        "views/scan_config.xml",
        # "views/nmap_scan_cron.xml",
    ],
    'application': True,
}