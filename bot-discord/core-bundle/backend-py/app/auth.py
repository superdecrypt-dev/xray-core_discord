def validate_internal_secret(received: str, expected: str) -> bool:
    return bool(expected) and received == expected
