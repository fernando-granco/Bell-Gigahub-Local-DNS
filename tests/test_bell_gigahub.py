"""Tests for the pure, network-free logic in bell_gigahub_pihole_dns.py.

These only cover functions that do not touch a real router: firmware risk
classification, IP validation, router response parsing, and the auth-key
hash. Everything else in the script (login, apply_change, the interactive
prompts) needs a live Gigahub and is out of scope for CI.
"""

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "bell_gigahub_pihole_dns.py"
spec = importlib.util.spec_from_file_location("bell_gigahub_pihole_dns", MODULE_PATH)
bell = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bell
spec.loader.exec_module(bell)


class TestIsTested:
    def test_known_model_and_affected_software(self):
        assert bell.is_tested("5690", "2.14.2") is True

    def test_known_model_and_good_software(self):
        assert bell.is_tested("5690", "3.11.6.2") is True

    def test_untested_model(self):
        assert bell.is_tested("1234", "2.14.2") is False

    def test_untested_software_on_known_model(self):
        assert bell.is_tested("5690", "9.9.9") is False


class TestRelayRisk:
    def test_known_bad_firmware(self):
        assert bell.relay_risk("2.14.2") == "known"

    def test_known_good_firmware(self):
        assert bell.relay_risk("3.11.6.2") == "none"

    def test_unseen_2x_firmware_is_suspected(self):
        assert bell.relay_risk("2.99.9") == "suspected"

    def test_unseen_3x_firmware_is_unknown(self):
        assert bell.relay_risk("3.0.0") == "unknown"

    def test_unrecognized_format_is_unknown(self):
        assert bell.relay_risk("weird-build") == "unknown"


class TestIsPrivateIpv4:
    @pytest.mark.parametrize(
        "address",
        ["192.168.2.10", "10.0.0.1", "172.16.5.5"],
    )
    def test_private_addresses(self, address):
        assert bell.is_private_ipv4(address) is True

    @pytest.mark.parametrize(
        "address",
        ["8.8.8.8", "1.1.1.1"],
    )
    def test_public_addresses(self, address):
        assert bell.is_private_ipv4(address) is False

    def test_invalid_address_is_not_private(self):
        assert bell.is_private_ipv4("not-an-ip") is False

    def test_ipv6_address_does_not_raise(self):
        # ip_address() accepts IPv6 too; this only asserts no crash either way.
        bell.is_private_ipv4("::1")


class TestCheckOk:
    def test_suffix_match_is_ok(self):
        action = {"error": {"description": "XMO_NO_ERR", "code": 0}}
        bell.check_ok(action, "test action")  # must not raise

    def test_legacy_code_with_no_description_is_ok(self):
        action = {"error": {"description": "", "code": 16777238}}
        bell.check_ok(action, "test action")  # must not raise

    def test_real_error_raises(self):
        action = {"error": {"description": "XMO_AUTHENTICATION_ERR", "code": 1}}
        with pytest.raises(RuntimeError, match="test action failed"):
            bell.check_ok(action, "test action")

    def test_unknown_error_with_no_description_raises(self):
        action = {"error": {"description": "", "code": 999}}
        with pytest.raises(RuntimeError):
            bell.check_ok(action, "test action")


class TestComputeAuthKey:
    def test_matches_expected_sha512(self):
        api = bell.GigahubAPI.__new__(bell.GigahubAPI)
        api.ha1 = "deadbeef"
        result = api._compute_auth_key(req_id=1, cnonce="12345")
        expected = hashlib.sha512(
            "deadbeef:1:12345:JSON:/cgi/json-req".encode()
        ).hexdigest()
        assert result == expected

    def test_different_inputs_produce_different_keys(self):
        api = bell.GigahubAPI.__new__(bell.GigahubAPI)
        api.ha1 = "deadbeef"
        assert api._compute_auth_key(1, "a") != api._compute_auth_key(2, "a")
