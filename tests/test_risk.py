from incident_response_analyzer.events import SecurityEvent
from incident_response_analyzer.risk import calculate_risk_score

def test_suspicious_login_with_8_failed_attempts_scores_60():
    event = SecurityEvent(
        event_type="suspicious_login",
        source_ip="192.168.1.42",
        username="jsmith",
        failed_attempts=8,
    )
    
    score = calculate_risk_score(event)
    assert score == 60


def test_suspicious_login_with_10_failed_attempts_scores_90():
    event = SecurityEvent(
        event_type="suspicious_login",
        source_ip="10.0.0.25",
        username="admin",
        failed_attempts=10,
    )
    
    score = calculate_risk_score(event)
    assert score == 90