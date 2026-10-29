import re
from pathlib import Path
from urllib.parse import urlparse

from .models import BankaiError

LOOK_IN = ("wrangler.toml", "wrangler.json", "wrangler.jsonc", "package.json", "README.md",
           "index.html", "CNAME")


def resolve_repo(source, workdir=None):
    path = Path(source.strip()).expanduser().resolve()
    if not path.is_dir():
        raise BankaiError(f"Dossier introuvable : {path}")
    return path


def ownership_hint(repo, url):
    host = urlparse(url).hostname or ""
    worker = host.split(".")[0]

    for name in LOOK_IN:
        f = repo / name
        if not f.is_file():
            continue
        txt = f.read_text(errors="ignore")
        if host and host in txt:
            return f"le domaine {host} apparaît dans {name}"
        if name.startswith("wrangler") and re.search(rf"name\s*[=:]\s*[\"']{re.escape(worker)}[\"']", txt):
            return f"le Worker « {worker} » est déclaré dans {name}"
    return None
