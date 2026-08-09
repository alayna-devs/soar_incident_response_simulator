import pytest

from incident_response_analyzer.events import (
    InvalidSecurityEventError,
    parse_security_event
)

def test_parse_security_event_returns_security_event():
    raw_event = {
        "event_type": "suspicious_login",
        "source_ip": "192.168.1.42",
        "username": "jsmith",
        "failed_attempts": 8,
    }
    
    event = parse_security_event(raw_event)
    
    assert event.event_type == "suspicious_login"
    assert event.source_ip == "192.168.1.42"
    assert event.username == "jsmith"
    assert event.failed_attempts == 8


def test_parse_security_event_rejects_missing_fields():
    raw_event = {
        "source_ip": "192.168.1.42",
    }
    
    with pytest.raises(InvalidSecurityEventError) as error: 
        parse_security_event(raw_event)
    
    assert "Missing required fields" in str(error.value)
    assert "event_type" in str(error.value)
    assert "username" in str(error.value)
    assert "failed_attempts" in str(error.value)


def test_parse_security_event_rejects_non_dictionary_input():
    with pytest.raises(InvalidSecurityEventError) as error:
        parse_security_event("not a dictionary")
        
    assert str(error.value) == "Security event must be a dictionary."
    
    
def test_parse_security_event_rejects_invalid_ip_address():
    raw_event = {
        "event_type": "suspicious_login",
        "source_ip": "not-an-ip",
        "username": "jsmith",
        "failed_attempts": 8,
    }

    with pytest.raises(InvalidSecurityEventError) as error:
        parse_security_event(raw_event)

    assert str(error.value) == "source_ip must be a valid IP address"


def test_parse_security_event_rejects_non_integer_failed_attempts():
    raw_event = {
        "event_type": "suspicious_login",
        "source_ip": "192.168.1.42",
        "username": "jsmith",
        "failed_attempts": "8",
    }

    with pytest.raises(InvalidSecurityEventError) as error:
        parse_security_event(raw_event)

    assert str(error.value) == "failed_attempts must be an integer"


def test_parse_security_event_rejects_negative_failed_attempts():
    raw_event = {
        "event_type": "suspicious_login",
        "source_ip": "192.168.1.42",
        "username": "jsmith",
        "failed_attempts": -1,
    }

    with pytest.raises(InvalidSecurityEventError) as error:
        parse_security_event(raw_event)

    assert str(error.value) == "failed_attempts cannot be negative"