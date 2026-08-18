from incident_response_analyzer.events import SecurityEvent

def calculate_risk_score(event: SecurityEvent) -> int:
    score = 0
    
    if event.event_type == "suspicious_login":
        score += 20
    
    if event.failed_attempts >= 5:
        score += 40
        
    if event.failed_attempts >= 10:
        score += 30
        
    return score

def classify_severity(score: int) -> str:
    if score >= 80:
        return "HIGH"
    
    if score >= 40:
        return "MEDIUM"
    
    return "LOW"