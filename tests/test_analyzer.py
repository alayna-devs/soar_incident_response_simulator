from incident_response_analyzer.analyzer import analyze_event

def test_analyze_event_returns_complete_incident_analysis():
    raw_event = {
        "event_type": "suspicious_login",
        "source_ip": "192.168.1.42",
        "username": "jsmith",
        "failed_attempts": 8,
    }
    
    analysis = analyze_event(raw_event)
    
    assert analysis.event.username == "jsmith"
    assert analysis.risk_score == 60
    assert analysis.severity == "MEDIUM"
    assert analysis.recommended_actions == [
        "create_incident",
        "notify_administrator",
        "monitor_source_ip",
    ]
