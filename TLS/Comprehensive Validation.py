import re
from decimal import Decimal
from typing import Any, Dict, List

class BankingInputValidator:
    def __init__(self):
        # Banking-specific validation patterns
        self.patterns = {
            'account_number': r'^[0-9]{10,12}$',
            'routing_number': r'^[0-9]{9}$',
            'amount': r'^\d+\.\d{2}$',
            'currency_code': r'^[A-Z]{3}$',
            'transaction_ref': r'^[A-Z0-9\-]{8,20}$'
        }
        
        # Dangerous patterns to reject
        self.dangerous_patterns = [
            r'(\%27)|(\')|(\-\-)|(%23)|(#)',  # SQL injection
            r'((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)',  # XSS
            r'((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))',  # Script injection
        ]
    
    def validate_transaction_request(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate transaction request data"""
        
        errors = []
        
        # Required fields validation
        required_fields = ['from_account', 'to_account', 'amount', 'currency']
        for field in required_fields:
            if field not in data:
                errors.append(f"Missing required field: {field}")
        
        # Account number validation
        if 'from_account' in data:
            if not self.validate_account_number(data['from_account']):
                errors.append("Invalid from_account format")
        
        if 'to_account' in data:
            if not self.validate_account_number(data['to_account']):
                errors.append("Invalid to_account format")
        
        # Amount validation
        if 'amount' in data:
            if not self.validate_amount(data['amount']):
                errors.append("Invalid amount format")
            elif Decimal(str(data['amount'])) <= 0:
                errors.append("Amount must be positive")
            elif Decimal(str(data['amount'])) > Decimal('1000000'):
                errors.append("Amount exceeds maximum limit")
        
        # Currency validation
        if 'currency' in data:
            if not self.validate_currency(data['currency']):
                errors.append("Invalid currency code")
        
        # Check for malicious patterns
        for field, value in data.items():
            if isinstance(value, str):
                if self.contains_dangerous_patterns(value):
                    errors.append(f"Invalid characters in {field}")
        
        if errors:
            raise ValidationError(errors)
        
        return data
    
    def validate_account_number(self, account_number: str) -> bool:
        """Validate account number format"""
        if not isinstance(account_number, str):
            return False
        return bool(re.match(self.patterns['account_number'], account_number))
    
    def validate_amount(self, amount: Any) -> bool:
        """Validate monetary amount"""
        try:
            # Convert to Decimal for precise monetary calculations
            decimal_amount = Decimal(str(amount))
            return decimal_amount > 0 and decimal_amount.as_tuple().exponent >= -2
        except:
            return False
    
    def contains_dangerous_patterns(self, value: str) -> bool:
        """Check for dangerous injection patterns"""
        for pattern in self.dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        return False
