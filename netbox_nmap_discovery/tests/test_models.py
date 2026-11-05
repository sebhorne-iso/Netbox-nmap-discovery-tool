from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from ..crypto import CredentialDecryptionError
from ..models import CredentialProfile, RoleRule, ScanTarget


class CredentialProfileTests(TestCase):

    def test_secrets_are_encrypted_at_rest(self):
        profile = CredentialProfile(name="ssh", kind="ssh", username="netops")
        profile.secret = "s3cret-password"
        profile.enable_secret = "enable!"
        profile.save()
        stored = CredentialProfile.objects.get(pk=profile.pk)
        self.assertNotIn("s3cret", stored.encrypted_secret)
        self.assertEqual(stored.secret, "s3cret-password")
        self.assertEqual(stored.to_ssh_credential().enable_secret, "enable!")
        # The change log representation never contains ciphertext
        serialized = stored.serialize_object()
        self.assertFalse(any(key.startswith("encrypted_") for key in serialized))

    def test_snmp_credential_conversion(self):
        profile = CredentialProfile(name="v3", kind="snmp-v3", username="mon", snmp_auth_protocol="sha256",
                                    snmp_priv_protocol="aes128", port=1161)
        profile.auth_key = "authpassphrase"
        profile.priv_key = "privpassphrase"
        profile.save()
        credential = CredentialProfile.objects.get(pk=profile.pk).to_snmp_credential()
        self.assertEqual((credential.version, credential.username, credential.port), ("3", "mon", 1161))
        self.assertEqual(credential.priv_key, "privpassphrase")

    def test_key_change_is_detected(self):
        profile = CredentialProfile(name="c", kind="snmp-v2c")
        profile.secret = "public"
        profile.save()
        with override_settings(PLUGINS_CONFIG={"netbox_nmap_discovery": {"encryption_key": "another-key"}}):
            from unittest import mock

            with mock.patch("netbox.plugins.get_plugin_config", return_value="another-key"):
                with self.assertRaises(CredentialDecryptionError):
                    _ = CredentialProfile.objects.get(pk=profile.pk).secret

    def test_key_rotation(self):
        from unittest import mock

        from .. import crypto

        profile = CredentialProfile(name="r", kind="snmp-v2c")
        profile.secret = "community"
        profile.save()
        with mock.patch("netbox.plugins.get_plugin_config", return_value=["new-key", "test-encryption-key"]):
            rotated = crypto.rotate(profile.encrypted_secret)
        with mock.patch("netbox.plugins.get_plugin_config", return_value="new-key"):
            self.assertEqual(crypto.decrypt(rotated), "community")


class ScanTargetValidationTests(TestCase):

    def test_valid_targets(self):
        targets = "10.0.0.0/24\n10.0.1.5\n10.0.2.10-20\n# comment\nrouter1.example.com"
        ScanTarget(name="ok", targets=targets).full_clean()

    def test_invalid_targets(self):
        for value in ("10.0.0.0/8", "-oN /tmp/x", "10.0.0.0/24; rm -rf /", "not a target!"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                ScanTarget(name="bad", targets=value).full_clean()

    def test_custom_arguments_are_restricted(self):
        target = ScanTarget(name="c", targets="10.0.0.0/24", scan_profile="custom",
                            custom_nmap_args="-sT -p 22,443 -T4")
        target.full_clean()
        for args in ("--script vuln", "-oN /etc/passwd", "-iL /etc/hosts", "--datadir /tmp"):
            target.custom_nmap_args = args
            with self.subTest(args=args), self.assertRaises(ValidationError):
                target.full_clean()

    def test_covers(self):
        target = ScanTarget(name="c", targets="10.0.0.0/24", exclusions="10.0.0.128/25")
        self.assertTrue(target.covers("10.0.0.5"))
        self.assertFalse(target.covers("10.0.0.200"))
        self.assertFalse(target.covers("10.0.1.1"))


class RoleRuleValidationTests(TestCase):

    def test_requires_condition_and_valid_regex(self):
        from dcim.models import DeviceRole

        role = DeviceRole.objects.create(name="r", slug="r")
        with self.assertRaises(ValidationError):
            RoleRule(name="empty", role=role).full_clean()
        with self.assertRaises(ValidationError):
            RoleRule(name="bad", role=role, hostname_regex="(").full_clean()
        RoleRule(name="ok", role=role, open_ports="9100, 631").full_clean()
