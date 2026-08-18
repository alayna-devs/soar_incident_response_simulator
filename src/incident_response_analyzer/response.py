# Cybersecurity term: this is a simple response playbook.

def recommend_response_actions(severity: str) -> list[str]:
    if severity == "HIGH":
        return [
            "create_incident",
            "notify_administrator",
            "recommend_ip_block",
            "require_password_reset",
        ]
        
    if severity == "MEDIUM":
        return [
            "create_incident",
            "notify_administrator",
            "monitor_source_ip",
        ]
        
    return [
        "log_event",
    ]