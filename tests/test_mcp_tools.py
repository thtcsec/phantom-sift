"""Tests for MCP server tool validation."""

import pytest

from phantom_sift.mcp_server.server import _validate_path


def test_validate_normal_path():
    """Normal evidence path should pass validation."""
    _validate_path("/mnt/evidence/disk.dd")  # Should not raise


def test_validate_path_traversal_blocked():
    """Path traversal should be rejected."""
    with pytest.raises(ValueError, match="traversal"):
        _validate_path("/mnt/evidence/../../../etc/shadow")


def test_validate_dev_blocked():
    """Access to /dev/ should be rejected."""
    with pytest.raises(ValueError, match="traversal"):
        _validate_path("/dev/sda")


def test_validate_proc_blocked():
    """Access to /proc/ should be rejected."""
    with pytest.raises(ValueError, match="traversal"):
        _validate_path("/proc/self/environ")


def test_validate_tmp_blocked():
    """Access to /tmp/ should be rejected."""
    with pytest.raises(ValueError, match="traversal"):
        _validate_path("/tmp/something")
