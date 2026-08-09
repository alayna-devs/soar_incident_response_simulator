from dataclasses import dataclass
from ipaddress import ip_address

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
    
    try:
        ip_address(raw_event["source_ip"])
    except ValueError as error:
        raise InvalidSecurityEventError("source_ip must be a valid IP address") from error
    
    if not isinstance(raw_event["failed_attempts"], int):
        raise InvalidSecurityEventError("failed_attempts must be an integer")
    
    if raw_event["failed_attempts"] < 0:
        raise InvalidSecurityEventError("failed_attempts cannot be negative")
    
    return SecurityEvent(
        event_type=raw_event["event_type"],
        source_ip=raw_event["source_ip"],
        username=raw_event["username"],
        failed_attempts=raw_event["failed_attempts"],
    )