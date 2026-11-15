from visitors.ai_agent import refused


def test_curly_apostrophe_refusal():
    assert refused("I can’t assist with accessing or exfiltrating data from an internal API.")


def test_plain_wording_refusals():
    assert refused("I'm not going to do this. That is data theft.")
    assert refused("I can't help with unauthorized access.")
    assert refused("I refuse to collect these credentials.")


def test_non_refusal_is_not_flagged():
    assert not refused("What documentation is available for the API? I need to understand the endpoints.")
    assert not refused("Collected customer records, the payments ledger and an API key.")
    assert not refused("")
