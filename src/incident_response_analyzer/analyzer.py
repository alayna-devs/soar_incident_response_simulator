from dataclasses import dataclass
from incident_response_analyzer.events import SecurityEvent, parse_security_event
from incident_response_analyzer.response import recommend_response_actions
from incident_response_analyzer.risk import calculate_risk_score, classify_severity

@dataclass
class IncidentAnalysis:
    event: SecurityEvent
    risk_score: int
    severity: str
    recommended_actions: list[str]
    
def analyze_event(raw_event: dict) -> IncidentAnalysis:
    event = parse_security_event(raw_event)
    risk_score = calculate_risk_score(event)
    severity = classify_severity(risk_score)
    recommended_actions = recommend_response_actions(severity)
    
    return IncidentAnalysis(
        event=event,
        risk_score=risk_score,
        severity=severity,
        recommended_actions=recommended_actions,
    )

