"""Pruebas unitarias para el motor auditor (src/auditor.py)."""

from src.auditor import extract_fixed_version, process_vulnerability_record


def test_extract_fixed_version_found():
    """Verifica que identifique el parche oficial cuando la versión es superior."""
    mock_vuln = {
        "affected": [
            {
                "package": {"name": "requests"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "2.0.0"}, {"fixed": "2.31.0"}],
                    }
                ],
            }
        ]
    }
    assert extract_fixed_version(mock_vuln, "requests", "2.25.0") == "2.31.0"


def test_extract_fixed_version_discriminates_older_branches():
    """Verifica que descarte versiones fijas inferiores a la actual (ej. 2.12.3 vs 2.14.1)."""
    mock_vuln = {
        "affected": [
            {
                "package": {"name": "log4j-core"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "2.0"}, {"fixed": "2.12.3"}],
                    },
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}],
                    },
                ],
            }
        ]
    }
    # Teniendo 2.14.1, no debe sugerir 2.12.3 sino 2.15.0
    assert extract_fixed_version(mock_vuln, "log4j-core", "2.14.1") == "2.15.0"


def test_extract_fixed_version_not_found():
    """Verifica que retorne None cuando no hay parches registrados (Zero-Day)."""
    mock_vuln = {
        "affected": [
            {
                "package": {"name": "test-pkg"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0.0"}],
                    }
                ],
            }
        ]
    }
    assert extract_fixed_version(mock_vuln, "test-pkg", "1.0.0") is None


def test_process_vulnerability_record_zero_day_flag():
    """Valida que un registro sin parche marque has_patch como False."""
    mock_vuln = {
        "id": "CVE-2026-TEST",
        "summary": "Falla crítica sin parche",
        "affected": [],
    }
    dep = {"name": "demo-lib", "ecosystem": "PyPI", "version": "1.0.0"}

    result = process_vulnerability_record(mock_vuln, dep)
    assert result["has_patch"] is False
    assert result["fixed_version"] is None
    assert result["id"] == "CVE-2026-TEST"
