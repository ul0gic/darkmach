"""Tests for darkmach._paths — directory resolution and env-var overrides."""

from __future__ import annotations

from pathlib import Path

from darkmach._paths import (
    BRIDGE_SOCKET,
    CRYPT_CACHE,
    DYLIB_DIR,
    OUTPUT_DIR,
    PATCH_DIR,
    app_bundle_dir,
    app_dynamic_dir,
    app_output_dir,
    app_static_dir,
)


class TestPackageRelativePaths:
    """DYLIB_DIR and PATCH_DIR resolve relative to the installed package."""

    def test_dylib_dir_lives_inside_darkmach_package(self):
        # …/darkmach/dylibs/build
        assert DYLIB_DIR.parent.parent.name == "darkmach"
        assert DYLIB_DIR.parent.name == "dylibs"
        assert DYLIB_DIR.name == "build"

    def test_patch_dir_lives_inside_darkmach_package(self):
        # …/darkmach/patch
        assert PATCH_DIR.parent.name == "darkmach"
        assert PATCH_DIR.name == "patch"

    def test_dylib_and_patch_share_package_parent(self):
        assert DYLIB_DIR.parent.parent == PATCH_DIR.parent

    def test_bridge_socket_path(self):
        assert BRIDGE_SOCKET == "/tmp/darkmach-bridge.sock"


class TestOutputDirDefault:
    """OUTPUT_DIR defaults to $PWD/output unless DARKMACH_OUTPUT is set."""

    def test_output_dir_is_a_path(self):
        assert isinstance(OUTPUT_DIR, Path)

    def test_crypt_cache_is_under_output(self):
        assert CRYPT_CACHE == OUTPUT_DIR / ".cache" / "crypt"


class TestAppOutputDirs:
    """Per-app output directory helpers."""

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
