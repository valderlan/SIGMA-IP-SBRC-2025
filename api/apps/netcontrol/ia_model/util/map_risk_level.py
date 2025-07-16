def map_risk_level(value):

    risk_mapping = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "unknown": 1,
        "none": 0,
    }
    return risk_mapping.get(str(value).lower(), 0)
