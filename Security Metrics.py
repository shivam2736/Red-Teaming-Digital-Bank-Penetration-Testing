security_kpis = {
    'vulnerability_metrics': {
        'critical_vulns_open': {'target': 0, 'current': 8, 'trend': 'decreasing'},
        'mean_time_to_patch': {'target': '24h', 'current': '72h', 'trend': 'improving'},
        'security_test_coverage': {'target': '95%', 'current': '60%', 'trend': 'increasing'}
    },
    'incident_response': {
        'mean_time_to_detection': {'target': '5min', 'current': '4h', 'trend': 'improving'},
        'mean_time_to_containment': {'target': '15min', 'current': '24h', 'trend': 'improving'},
        'false_positive_rate': {'target': '5%', 'current': '23%', 'trend': 'decreasing'}
    },
    'compliance_metrics': {
        'pci_compliance_score': {'target': '100%', 'current': '67%', 'trend': 'increasing'},
        'failed_audits': {'target': 0, 'current': 3, 'trend': 'decreasing'},
        'policy_compliance': {'target': '98%', 'current': '75%', 'trend': 'increasing'}
    }
}
