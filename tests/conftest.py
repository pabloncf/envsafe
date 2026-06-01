"""Shared pytest fixtures for envsafe tests."""

import pytest


@pytest.fixture
def tmp_project(tmp_path):
    """Return a temporary directory that acts as a fake project root."""
    return tmp_path
