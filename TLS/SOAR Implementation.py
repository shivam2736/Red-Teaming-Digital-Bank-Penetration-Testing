class SecurityOrchestrator:
    def __init__(self):
        self.playbooks = {
            'sql_injection_detected': self.handle_sql_injection,
            'authentication_bypass': self.handle_auth_bypass,
            'data_exfiltration': self.handle_data_exfiltration,
            'account_takeover': self.handle_account_takeover
        }
        
    def handle_security_event(self, event):
        """Orchestrate response to security events"""
        
        event_type = event['type']
        severity = event['severity']
        
        # Execute appropriate playbook
        if event_type in self.playbooks:
            response = self.playbooks[event_type](event)
        else:
            response = self.handle_generic_incident(event)
        
        # Log response actions
        self.log_response_actions(event, response)
        
        # Notify stakeholders
        self.notify_stakeholders(event, response)
        
        return response
    
    def handle_sql_injection(self, event):
        """Automated response to SQL injection"""
        actions = []
        
        # Immediate containment
        if event['severity'] == 'Critical':
            # Block source IP
            self.block_ip_address(event['source_ip'])
            actions.append(f"Blocked IP: {event['source_ip']}")
            
            # Disable affected endpoint
            self.disable_endpoint(event['endpoint'])
            actions.append(f"Disabled endpoint: {event['endpoint']}")
            
            # Alert security team
            self.alert_security_team(event)
            actions.append("Security team alerted")
        
        return {'actions': actions, 'status': 'contained'}
