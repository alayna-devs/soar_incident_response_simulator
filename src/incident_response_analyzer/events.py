from dataclasses import dataclass

@dataclass
class SecurityEvent:
    event_type: str
    source_ip: str
    username: str
    failed_attempts: int

def parse_security_event(raw_event: dict) -> SecurityEvent:
    return SecurityEvent(
        event_type=raw_event["event_type"],
        source_ip=raw_event["source_ip"],
        username=raw_event["username"],
        failed_attempts=raw_event["failed_attempts"],
    )