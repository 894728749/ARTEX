import json
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

import chromium_privacy_launcher as launcher


class ChromiumPrivacyLauncherTests(unittest.TestCase):
    def fresh_profile(self) -> Path:
        profile = Path(tempfile.mkdtemp(prefix=launcher.PROFILE_PREFIX, dir="/tmp"))
        self.addCleanup(shutil.rmtree, profile, ignore_errors=True)
        return profile

    def test_writes_only_required_policy_with_private_permissions(self) -> None:
        profile = self.fresh_profile()
        pref = launcher.prepare_profile(profile)
        self.assertEqual(
            json.loads(pref.read_text(encoding="utf-8")),
            {"webrtc": {"ip_handling_policy": "disable_non_proxied_udp"}},
        )
        self.assertEqual(stat.S_IMODE(pref.stat().st_mode), 0o600)

    def test_rejects_paths_outside_tmp_and_wrong_prefix(self) -> None:
        with tempfile.TemporaryDirectory(prefix=launcher.PROFILE_PREFIX, dir="/var/tmp") as outside:
            with self.assertRaises(ValueError):
                launcher.prepare_profile(outside)
        wrong_prefix = Path(tempfile.mkdtemp(prefix="not-playwright-", dir="/tmp"))
        self.addCleanup(shutil.rmtree, wrong_prefix, ignore_errors=True)
        with self.assertRaises(ValueError):
            launcher.prepare_profile(wrong_prefix)

    def test_rejects_symlink_profile(self) -> None:
        real = self.fresh_profile()
        link = real.with_name(real.name + "-link")
        link.symlink_to(real, target_is_directory=True)
        self.addCleanup(lambda: link.unlink(missing_ok=True))
        with self.assertRaises(ValueError):
            launcher.prepare_profile(link)

    def test_refuses_existing_profile_contents_without_changing_them(self) -> None:
        profile = self.fresh_profile()
        sentinel = profile / "keep.txt"
        sentinel.write_text("user data", encoding="utf-8")
        with self.assertRaises(ValueError):
            launcher.prepare_profile(profile)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "user data")
        self.assertFalse((profile / "Default").exists())

    def test_requires_one_user_data_dir_argument_and_preserves_path_forms(self) -> None:
        self.assertEqual(
            launcher.user_data_dir_from_args(["--headless", "--user-data-dir", "/tmp/a"]),
            "/tmp/a",
        )
        self.assertEqual(
            launcher.user_data_dir_from_args(["--user-data-dir=/tmp/a"]), "/tmp/a"
        )
        for args in ([], ["--user-data-dir", "/tmp/a", "--user-data-dir=/tmp/b"]):
            with self.subTest(args=args), self.assertRaises(ValueError):
                launcher.user_data_dir_from_args(args)


if __name__ == "__main__":
    unittest.main()
