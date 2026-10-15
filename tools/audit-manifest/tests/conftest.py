"""Shared pytest fixtures for the audit-manifest suite."""

import pytest

from audit_manifest.checkout import SourceReader


@pytest.fixture(autouse=True)
def _clear_source_reader_cache():
    """SourceReader memoizes file reads for the life of one checkout state.

    That cache is process-global, so every test starts from an empty one:
    a test that writes a source file, reads it, rewrites it and reads again
    must never observe an earlier read of the same path.
    """
    SourceReader.invalidate()
    yield
    SourceReader.invalidate()
