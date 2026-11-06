"""Explicit map filters: activity is not automatically a threat."""

GEO_MODES = {
    'activity': [],
    'blocked': ["rule_action = 'block'"],
    'threats': ["threat_score > 70"],
    'blocked_outbound': ["direction = 'outbound'", "rule_action = 'block'"],
}
