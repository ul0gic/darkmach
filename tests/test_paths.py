"""Tests for darkmach._paths — project root and directory resolution."""

from __future__ import annotations

from pathlib import Path

from darkmach._paths import (
    BRIDGE_SOCKET,
    CRYPT_CACHE,
    DYLIB_DIR,
    OUTPUT_DIR,
    PATCH_DIR,
    ROOT,
    SRC_DIR,
    app_bundle_dir,
    app_dynamic_dir,
    app_output_dir,
    app_static_dir,
)


class TestProjectPaths:
    """Verify that resolved paths point to the expected locations."""

    def test_root_contains_pyproject_toml(self):
        assert (ROOT / "pyproject.toml").exists(), f"ROOT ({ROOT}) does not contain pyproject.toml"

    def test_src_dir_is_under_root(self):
        assert SRC_DIR == ROOT / "src"

    def test_dylib_dir_is_under_src(self):
        assert DYLIB_DIR == SRC_DIR / "dylibs" / "build"

    def test_patch_dir_is_under_src(self):
        assert PATCH_DIR == SRC_DIR / "patch"

    def test_output_dir_is_under_root(self):
        assert OUTPUT_DIR == ROOT / "output"

    def test_crypt_cache_is_under_output(self):
        assert CRYPT_CACHE == OUTPUT_DIR / ".cache" / "crypt"

    def test_bridge_socket_path(self):
        assert BRIDGE_SOCKET == "/tmp/darkmach-bridge.sock"


class TestAppOutputDirs:
    """Verify per-app output directory helpers."""

    def test_app_output_dir_basic(self):
        result = app_output_dir("MyApp")
        assert result == OUTPUT_DIR / "myapp"

    def test_app_output_dir_strips_app_suffix(self):
        result = app_output_dir("MyApp.app")
        assert result == OUTPUT_DIR / "myapp"

    def test_app_output_dir_replaces_spaces(self):
        result = app_output_dir("My Cool App")
        assert result == OUTPUT_DIR / "my-cool-app"

    def test_app_output_dir_replaces_underscores(self):
        result = app_output_dir("my_app")
        assert result == OUTPUT_DIR / "my-app"

    def test_app_static_dir(self):
        result = app_static_dir("TestApp")
        assert result == OUTPUT_DIR / "testapp" / "static"

    def test_app_dynamic_dir(self):
        result = app_dynamic_dir("TestApp")
        assert result == OUTPUT_DIR / "testapp" / "dynamic"

    def test_app_bundle_dir(self):
        result = app_bundle_dir("TestApp")
        assert result == OUTPUT_DIR / "testapp" / "bundle"

    def test_all_app_dirs_share_parent(self):
        """Static, dynamic, and bundle dirs should all be siblings under the app root."""
        parent = app_output_dir("X")
        assert app_static_dir("X") == parent / "static"
        assert app_dynamic_dir("X") == parent / "dynamic"
        assert app_bundle_dir("X") == parent / "bundle"

    def test_app_output_dir_returns_path_object(self):
        assert isinstance(app_output_dir("anything"), Path)
