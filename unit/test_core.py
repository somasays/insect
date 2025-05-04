@pytest.fixture
def mock_config():
    """Create a mock configuration for testing."""
    return {
        "general": {
            "include_hidden": False,
            "max_depth": 3
        },
        "patterns": {
            "include": ["*"],
            "exclude": ["*/node_modules/*", "*/.git/*", "*.pyc"]
        },
        "analyzers": {
            "static": True,
            "binary": False,
            "config": True
        },
        "severity": {
            "min_level": "low",
            "min_confidence": "medium"
        }
    } 