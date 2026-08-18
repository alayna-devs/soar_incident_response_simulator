from incident_response_analyzer.response import recommend_response_actions


def test_recommend_response_actions_for_high_severity():
    actions = recommend_response_actions("HIGH")

    assert actions == [
        "create_incident",
        "notify_administrator",
        "recommend_ip_block",
        "require_password_reset",
    ]


def test_recommend_response_actions_for_medium_severity():
    actions = recommend_response_actions("MEDIUM")

    assert actions == [
        "create_incident",
        "notify_administrator",
        "monitor_source_ip",
    ]


def test_recommend_response_actions_for_low_severity():
    actions = recommend_response_actions("LOW")

    assert actions == [
        "log_event",
    ]