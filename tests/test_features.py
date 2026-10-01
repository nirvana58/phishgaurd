from core.features import extract_features, normalize_url


def test_bare_domain_is_normalized_for_scanning():
    assert normalize_url("example.com") == "https://example.com"
    assert extract_features("example.com")[13] == 0
    assert extract_features(normalize_url("example.com"))[1:4] == extract_features("https://example.com")[1:4]


def test_explicit_http_is_not_marked_https():
    assert extract_features("http://example.com")[13] == 0