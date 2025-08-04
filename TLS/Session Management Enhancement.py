import secrets
import hashlib
from datetime import datetime, timedelta

class SecureSessionManager:
    def __init__(self):
        self.session_timeout = 900  # 15 minutes
        self.max_concurrent_sessions = 3
        
    def create_session(self, user_id):
        """Create cryptographically secure session"""
        
        # Generate secure session ID
        session_id = secrets.token_urlsafe(32)
        
        # Create session data
        session_data = {
            'user_id': user_id,
            'created_at': datetime.utcnow(),
            'last_activity': datetime.utcnow(),
            'ip_address': self.get_client_ip(),
            'user_agent': self.get_user_agent(),
            'csrf_token': secrets.token_urlsafe(32)
        }
        
        # Store session with expiration
        self.store_session(session_id, session_data)
        
        # Enforce concurrent session limits
        self.enforce_session_limits(user_id)
        
        return session_id
    
    def validate_session(self, session_id):
        """Validate and refresh session"""
        
        session_data = self.get_session(session_id)
        if not session_data:
            raise SessionError("Invalid session")
        
        # Check timeout
        if self.is_session_expired(session_data):
            self.destroy_session(session_id)
            raise SessionError("Session expired")
        
        # Update last activity
        session_data['last_activity'] = datetime.utcnow()
        self.store_session(session_id, session_data)
        
        return session_data
