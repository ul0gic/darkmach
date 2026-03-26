"""Shared pytest fixtures for the Darkmach test suite.

Provides:
  - fake_app_bundle: minimal .app directory with Info.plist and dummy binary
  - mock_subprocess_run: configurable CompletedProcess factory for otool/codesign/plutil mocking
  - mock_urlopen: context-manager mock for urllib.request.urlopen
"""

from __future__ import annotations

import json
import plistlib
import subprocess
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Fake .app bundle fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_app_bundle(tmp_path: Path) -> Path:
    """Create a minimal .app directory structure.

    Layout:
        tmp_path/FakeApp.app/
            Info.plist          (binary plist with CFBundleExecutable + CFBundleIdentifier)
            FakeApp             (dummy 4-byte binary)
            Wrapper/
                Inner.app/
                    Info.plist  (inner bundle plist with UIDeviceFamily)
                    Inner       (dummy binary)
    """
    app_dir = tmp_path / "FakeApp.app"
    app_dir.mkdir()

    # Info.plist (outer)
    plist_data = {
        "CFBundleExecutable": "FakeApp",
        "CFBundleIdentifier": "com.test.fakeapp",
        "CFBundleShortVersionString": "1.0",
    }
    (app_dir / "Info.plist").write_bytes(plistlib.dumps(plist_data))

    # Dummy binary
    (app_dir / "FakeApp").write_bytes(b"\xcf\xfa\xed\xfe")

    # Wrapper with inner iOS bundle
    wrapper = app_dir / "Wrapper"
    wrapper.mkdir()
    inner = wrapper / "Inner.app"
    inner.mkdir()

    inner_plist = {
        "CFBundleExecutable": "Inner",
        "CFBundleIdentifier": "com.test.inner",
        "CFBundleShortVersionString": "2.0",
        "UIDeviceFamily": [1, 2],
    }
    (inner / "Info.plist").write_bytes(plistlib.dumps(inner_plist))
    (inner / "Inner").write_bytes(b"\xcf\xfa\xed\xfe")

    return app_dir


# ---------------------------------------------------------------------------
# Subprocess mock fixture
# ---------------------------------------------------------------------------


def _make_completed_process(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["mock"], returncode=returncode, stdout=stdout, stderr=stderr
    )


@pytest.fixture()
def mock_subprocess_run():
    """Fixture that patches subprocess.run with a configurable side_effect.

    Returns a helper: call mock_subprocess_run(responses) where responses is
    a list of CompletedProcess objects or a single one used for all calls.

    Usage:
        def test_something(mock_subprocess_run):
            mock_run = mock_subprocess_run([
                _make_completed_process(stdout="some output"),
            ])
            # ... code that calls subprocess.run ...
            assert mock_run.call_count == 1
    """

    def _configure(responses=None, target="subprocess.run"):
        mock = MagicMock()
        if responses is None:
            mock.return_value = _make_completed_process()
        elif isinstance(responses, list):
            mock.side_effect = responses
        else:
            mock.return_value = responses
        patcher = patch(target, mock)
        patcher.start()
        # Store so the caller can stop it (pytest also cleans up via addcleanup)
        mock._patcher = patcher
        return mock

    yield _configure

    # cleanup is handled by individual patchers in the test


@pytest.fixture()
def mock_urlopen():
    """Fixture that patches urllib.request.urlopen.

    Returns a helper: call mock_urlopen(response_body, status=200).
    response_body can be a dict (JSON-serialized) or a string/bytes.
    """

    def _configure(body, status=200):
        if isinstance(body, dict):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.status = status
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        patcher = patch("urllib.request.urlopen", return_value=mock_resp)
        mock_fn = patcher.start()
        mock_fn._patcher = patcher
        return mock_fn

    yield _configure


# ---------------------------------------------------------------------------
# Helper factories available as module-level imports in tests
# ---------------------------------------------------------------------------

make_completed_process = _make_completed_process
