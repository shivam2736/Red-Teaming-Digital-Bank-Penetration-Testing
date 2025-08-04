import redis
from flask import request, jsonify
from functools import wraps

class BankingRateLimiter:
    def __init__(self):
        self.redis_client = redis.Redis(host='localhost', port=6379, db=0)
        self.rate_limits = {
            'authentication': {'requests': 5, 'window': 300},      # 5 attempts per 5 minutes
            'transactions': {'requests': 10, 'window': 60},        # 10 transactions per minute
            'account_queries': {'requests': 100, 'window': 3600},  # 100 queries per hour
            'default': {'requests': 1000, 'window': 3600}          # 1000 requests per hour
        }
    
    def rate_limit(self, endpoint_type='default'):
        """Rate limiting decorator"""
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                # Identify client
                client_id = self.get_client_identifier()
                
                # Check rate limit
                if self.is_rate_limited(client_id, endpoint_type):
                    return jsonify({
                        'error': 'Rate limit exceeded',
                        'retry_after': self.get_retry_after(client_id, endpoint_type)
                    }), 429
                
                # Record request
                self.record_request(client_id, endpoint_type)
                
                return f(*args, **kwargs)
            return wrapper
        return decorator
    
    def is_rate_limited(self, client_id, endpoint_type):
        """Check if client has exceeded rate limit"""
        limits = self.rate_limits[endpoint_type]
        key = f"rate_limit:{endpoint_type}:{client_id}"
        
        current_requests = self.redis_client.get(key)
        if current_requests is None:
            return False
        
        return int(current_requests) >= limits['requests']
