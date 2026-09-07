"""Environment configuration; credentials never enter report documents."""

import os
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.engine import make_url


@dataclass(frozen=True)
class Settings:
    database_url: str
    audit_path: Path

    def storage_paths(self) -> list[Path]:
        paths = [self.audit_path]
        url = make_url(self.database_url)
        if url.get_backend_name() == "sqlite" and url.database not in {None, "", ":memory:"}:
            paths.append(Path(url.database))
        return paths

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            database_url=os.environ.get("REDOPS_DATABASE_URL", "sqlite:///data/redops.db"),
            audit_path=Path(os.environ.get("REDOPS_AUDIT_PATH", "data/audit.jsonl")),
        )
