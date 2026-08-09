from dataclasses import dataclass

class InvalidSecurityEventError(ValueError):
    pass

@dataclass
class SecurityEvent:
    event_type: str
    source_ip: str
    username: str
    failed_attempts: int

def parse_security_event(raw_event: dict) -> SecurityEvent:
    if not isinstance(raw_event, dict):
        raise InvalidSecurityEventError("Security event must be a dictionary.")
    
    required_fields = {
        "event_type",
        "source_ip",
        "username",
        "failed_attempts",
    }
    
    missing_fields = required_fields - set(raw_event)
    
    if missing_fields:
        fields = ", ".join(sorted(missing_fields))
        raise InvalidSecurityEventError(f"Missing required fields: {fields}")
    
    return SecurityEvent(
        event_type=raw_event["event_type"],
        source_ip=raw_event["source_ip"],
        username=raw_event["username"],
        failed_attempts=raw_event["failed_attempts"],
    )