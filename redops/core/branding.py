"""Load the bundled RedOps mark for self-contained, offline report branding."""

import base64
from functools import lru_cache
from importlib.resources import files


@lru_cache(maxsize=1)
def logo_bytes() -> bytes:
    return files("redops").joinpath("web/static/redops-mark.png").read_bytes()


@lru_cache(maxsize=1)
def logo_data_uri() -> str:
    return "data:image/png;base64," + base64.b64encode(logo_bytes()).decode("ascii")
