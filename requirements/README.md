# Tested Linux dependency locks

Each `linux-pyX.Y-runtime.txt` includes runtime dependencies, the PostgreSQL driver
and the build backend. Each `-dev.txt` additionally includes test, browser and
packaging tools. Every dependency is pinned with SHA-256 hashes. Locks were
generated with pip-tools 7.6.1 in Linux x86_64 Python 3.11, 3.13 and 3.14 containers.
Other operating systems or architectures need their own tested resolution.

From the repository root, inside the corresponding Python environment:

```bash
python -m pip install --require-hashes -r requirements/linux-py3.13-dev.txt
python -m pip install --no-deps --no-build-isolation -e .
python -m pip check
```

Use the runtime file for an installation without development tools. Dependency
installation may use PyPI or a prepared wheelhouse. Runtime assessment, dashboard
and report operations can then run offline. `requirements.txt` remains the legacy
editable-install convenience file; it does not provide the locked release path.

To regenerate, install `pip-tools==7.6.1` in each supported Linux Python environment
and run `python scripts/compile_locks.py`. Review the resulting changes, run all CI
gates, and update container digests together when updating Python. Existing pins
are retained by pip-tools unless requirements change; use its documented upgrade
options for a deliberate dependency update. The generator is the authoritative
command; pip-tools may include `--no-index` in its generated comment when index
URL emission is disabled.

The test client uses `httpx2`. `compat.in` temporarily bounds AnyIO below 4.15 because
Starlette 1.6 imports a deprecated alias in its test client. This is a tested
compatibility constraint, not a warning filter. CI treats Python warnings as errors.

Container base digests tested with these locks:

| Base | SHA-256 manifest digest |
| --- | --- |
| Python 3.11 slim | `9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534` |
| Python 3.13 slim | `9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285` |
| Python 3.14 slim | `cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6` |
| PostgreSQL 17 | `67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675` |
