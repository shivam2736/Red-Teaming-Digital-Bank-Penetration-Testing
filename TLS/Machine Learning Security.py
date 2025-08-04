import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class BankingAnomalyDetector:
    def __init__(self):
        self.models = {
            'transaction_anomaly': IsolationForest(contamination=0.1),
            'login_anomaly': IsolationForest(contamination=0.05),
            'api_usage_anomaly': IsolationForest(contamination=0.1)
        }
        self.scalers = {
            'transaction': StandardScaler(),
            'login': StandardScaler(),
            'api_usage': StandardScaler()
        }
        
    def detect_transaction_anomaly(self, transaction_data):
        """Detect anomalous transaction patterns"""
        
        # Extract features
        features = self.extract_transaction_features(transaction_data)
        
        # Scale features
        features_scaled = self.scalers['transaction'].transform([features])
        
        # Predict anomaly
        anomaly_score = self.models['transaction_anomaly'].decision_function(features_scaled)[0]
        is_anomaly = self.models['transaction_anomaly'].predict(features_scaled)[0] == -1
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': anomaly_score,
            'risk_level': self.calculate_risk_level(anomaly_score)
        }
    
    def extract_transaction_features(self, transaction):
        """Extract features for anomaly detection"""
        return [
            transaction['amount'],
            transaction['hour_of_day'],
            transaction['day_of_week'],
            transaction['account_age_days'],
            transaction['avg_transaction_amount'],
            transaction['transaction_frequency'],
            transaction['geographical_distance']
        ]
