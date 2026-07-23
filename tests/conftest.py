"""Pytest configuration and shared fixtures."""

import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "asyncio: mark test as async")


@pytest.fixture(scope="session")
def event_loop_policy():
    """Use default asyncio event loop policy."""
    import asyncio
    return asyncio.DefaultEventLoopPolicy()
