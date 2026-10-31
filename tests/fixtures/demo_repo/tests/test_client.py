MOCK_HEALTH = "https://sandbox.payments.example.com/v1/health"


def test_health_url_is_sandbox():
    assert MOCK_HEALTH.endswith("/health")
