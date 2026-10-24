# Moriarty Backend

This directory contains the Python core of Moriarty, including the AST analyzer, patch comparator, adaptive agent planner, local SQLite application fixtures, evidence ledger, verdict engine, and verification test suite.

For full architectural documentation, demo walkthroughs, and setup instructions, please see the root [README.md](../README.md).

### Quick Commands

```powershell
# Run all tests
& "venv/Scripts/pytest.exe"

# Run the patch verification check
& "venv/Scripts/python.exe" check_patch_aware_loop.py
```
