from incident_response_analyzer.events import SecurityEvent
from incident_response_analyzer.risk import calculate_risk_score, classify_severity

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

def test_classify_severity_returns_high_for_score_80_or_above():
    assert classify_severity(80) == "HIGH"
    assert classify_severity(90) == "HIGH"


def test_classify_severity_returns_medium_for_score_40_to_79():
    assert classify_severity(40) == "MEDIUM"
    assert classify_severity(60) == "MEDIUM"
    assert classify_severity(79) == "MEDIUM"


def test_classify_severity_returns_low_for_score_below_40():
    assert classify_severity(0) == "LOW"
    assert classify_severity(39) == "LOW"