#!/usr/bin/env python3
"""Add the WebRTC privacy preference to a fresh Playwright Chromium profile."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path


CHROMIUM = os.environ['ARTEX_PRIVACY_CHROMIUM']
PROFILE_PREFIX = "playwright_chromiumdev_profile-"
WEBRTC_POLICY = "disable_non_proxied_udp"


def prepare_profile(user_data_dir: str | os.PathLike[str]) -> Path:
    """Write the single required WebRTC preference into a verified fresh profile.

    Playwright 1.64 creates a profile under /tmp with the Chromium prefix above.
    Refuse paths that could represent a persistent or caller-owned browser profile.
    """
    supplied = os.fspath(user_data_dir)
    if not os.path.isabs(supplied):
        raise ValueError("user-data-dir must be an absolute path")
    profile = Path(os.path.abspath(supplied))
    try:
        initial = profile.lstat()
    except OSError as exc:
        raise ValueError("user-data-dir must already exist") from exc
    if stat.S_ISLNK(initial.st_mode) or not stat.S_ISDIR(initial.st_mode):
        raise ValueError("user-data-dir must be a non-symlink directory")

    real_profile = Path(os.path.realpath(profile))
    real_tmp = Path(os.path.realpath("/tmp"))
    if profile != real_profile:
        raise ValueError("user-data-dir path must not traverse symlinks")
    try:
        relative = real_profile.relative_to(real_tmp)
    except ValueError as exc:
        raise ValueError("user-data-dir must be inside the real /tmp directory") from exc
    if len(relative.parts) != 1 or not relative.parts[0].startswith(PROFILE_PREFIX):
        raise ValueError("user-data-dir does not have the Playwright Chromium profile prefix")

    profile_fd = os.open(profile, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(profile_fd)
        if opened.st_uid != os.getuid():
            raise ValueError("user-data-dir is not owned by the current user")
        if not stat.S_ISDIR(opened.st_mode):
            raise ValueError("user-data-dir is not a directory")
        if os.listdir(profile_fd):
            raise ValueError("user-data-dir must be empty")

        os.mkdir("Default", mode=0o700, dir_fd=profile_fd)
        default_fd = os.open(
            "Default", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=profile_fd
        )
        try:
            fd = os.open(
                "Preferences",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=default_fd,
            )
            try:
                payload = json.dumps(
                    {"webrtc": {"ip_handling_policy": WEBRTC_POLICY}},
                    separators=(",", ":"),
                ).encode("utf-8")
                with os.fdopen(fd, "wb", closefd=True) as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod("Preferences", 0o600, dir_fd=default_fd, follow_symlinks=False)
            except BaseException:
                # fdopen owns and closes fd once constructed; close only if still open.
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
        finally:
            os.close(default_fd)
    finally:
        os.close(profile_fd)
    return profile / "Default" / "Preferences"


def user_data_dir_from_args(args: list[str]) -> str:
    values: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--user-data-dir":
            if i + 1 >= len(args) or args[i + 1].startswith("--"):
                raise ValueError("--user-data-dir requires a path")
            values.append(args[i + 1])
            i += 2
            continue
        if arg.startswith("--user-data-dir="):
            values.append(arg.partition("=")[2])
        i += 1
    if len(values) != 1 or not values[0]:
        raise ValueError("exactly one --user-data-dir path is required")
    return values[0]


def main(args: list[str] | None = None) -> int:
    chromium_args = list(sys.argv[1:] if args is None else args)
    try:
        prepare_profile(user_data_dir_from_args(chromium_args))
    except (OSError, ValueError) as exc:
        print(f"chromium privacy launcher: {exc}", file=sys.stderr)
        return 2
    os.execv(CHROMIUM, [CHROMIUM, *chromium_args])
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
