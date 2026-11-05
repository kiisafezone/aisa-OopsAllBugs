#!/usr/bin/env python3
"""AISA inventory: facts about the project (no judgements). Writes <workspace>/inventory.json."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from aisa_common import (CODE_LANGS, SCHEMA_VERSION, is_doc_path, is_test_path, iter_files, language_of,
                         now_iso, read_text, run_tool, save_json, scanner_parser, resolve_paths, tree_hash,
                         MAX_TEXT_BYTES)

MANIFEST_NAMES = {
    "package.json": "npm", "pyproject.toml": "python", "setup.py": "python", "setup.cfg": "python",
    "requirements.txt": "python", "Pipfile": "python", "go.mod": "go", "Cargo.toml": "rust",
    "pubspec.yaml": "dart/flutter", "pom.xml": "maven", "build.gradle": "gradle",
    "build.gradle.kts": "gradle", "composer.json": "php", "Gemfile": "ruby",
}
FRAMEWORK_HINTS = {
    "flask": "Flask", "fastapi": "FastAPI", "django": "Django", "sqlalchemy": "SQLAlchemy",
    "express": "Express", "react": "React", "vue": "Vue", "@angular/core": "Angular", "next": "Next.js",
    "svelte": "Svelte", "nestjs": "NestJS", "@nestjs/core": "NestJS", "flutter": "Flutter",
    "spring-boot": "Spring Boot", "laravel": "Laravel", "rails": "Rails", "prisma": "Prisma",
    "mongoose": "Mongoose", "sequelize": "Sequelize", "pytest": "pytest", "jest": "Jest",
    "psycopg": "PostgreSQL driver", "pymysql": "MySQL driver", "redis": "Redis client",
    "celery": "Celery", "tailwindcss": "Tailwind CSS", "baileys": "Baileys (WhatsApp)",
}
INFRA_PATTERNS = {
    "Dockerfile": r"(^|/)Dockerfile(\..+)?$", "docker-compose": r"(^|/)docker-compose\.ya?ml$",
    "GitHub Actions": r"^\.github/workflows/.+\.ya?ml$", "GitLab CI": r"(^|/)\.gitlab-ci\.yml$",
    "Jenkinsfile": r"(^|/)Jenkinsfile$", "Terraform": r"\.tf$", "Kubernetes manifests": r"(^|/)(k8s|kubernetes|helm)/",
    "Makefile": r"(^|/)Makefile$", "Procfile": r"(^|/)Procfile$",
}
DOC_NAMES = {"readme": r"^readme(\.\w+)?$", "license": r"^licen[sc]e(\.\w+)?$", "changelog": r"^changelog(\.\w+)?$",
             "contributing": r"^contributing(\.\w+)?$", "security": r"^security(\.\w+)?$"}
ENTRY_FILES = {"main.py", "app.py", "manage.py", "wsgi.py", "asgi.py", "server.js", "index.js", "app.js", "main.js",
               "main.ts", "index.ts", "main.dart", "main.go", "Main.java", "Program.cs", "index.php", "artisan"}


def build_inventory(source: Path) -> dict:
    skipped_dirs: list[str] = []
    files, langs, loc = [], Counter(), Counter()
    unreadable, binaries, largest = [], [], []
    manifests, infra, docs, tests, envfiles, entrypoints = [], {}, {}, [], [], []
    top_level: Counter = Counter()
    code_files = test_files = 0
    for p, rel in iter_files(source, ignore=True, skipped=skipped_dirs):
        size = p.stat().st_size
        name = rel.rsplit("/", 1)[-1]
        top_level[rel.split("/")[0] if "/" in rel else "(root)"] += 1
        files.append(rel)
        lang = language_of(rel)
        if lang:
            langs[lang] += 1
        text = read_text(p)
        if text is None:
            (unreadable if size > MAX_TEXT_BYTES else binaries).append(rel)
        elif lang in CODE_LANGS:
            n = sum(1 for ln in text.splitlines() if ln.strip())
            loc[lang] += n
            largest.append((n, rel))
            if is_test_path(rel):
                test_files += 1
                tests.append(rel)
            else:
                code_files += 1
            if name in ENTRY_FILES or "__main__" in text[:200000] and lang == "Python":
                entrypoints.append(rel)
        if name in MANIFEST_NAMES:
            manifests.append({"path": rel, "ecosystem": MANIFEST_NAMES[name]})
        for label, pat in INFRA_PATTERNS.items():
            if re.search(pat, rel):
                infra.setdefault(label, []).append(rel)
        for label, pat in DOC_NAMES.items():
            if "/" not in rel and re.match(pat, name, re.I):
                docs[label] = rel
        if re.match(r"^\.env(\..+)?$", name):
            envfiles.append(rel)
    frameworks = set()
    for m in manifests:
        t = (read_text(source / m["path"]) or "").lower()
        for key, label in FRAMEWORK_HINTS.items():
            if re.search(rf"(?<![\w-]){re.escape(key)}(?![\w-])", t):
                frameworks.add(label)
    git = {"present": (source / ".git").exists()}
    if git["present"]:
        base = ["git", "-C", str(source), "-c", "safe.directory=*"]
        rc, out, _ = run_tool(base + ["rev-list", "--count", "HEAD"], timeout=60)
        git["commit_count"] = int(out.strip()) if rc == 0 and out.strip().isdigit() else None
        rc, out, _ = run_tool(base + ["log", "-1", "--format=%H|%cI|%an"], timeout=60)
        if rc == 0 and "|" in out:
            h, d, a = out.strip().split("|", 2)
            git.update({"head": h, "last_commit_date": d})
    th, count = tree_hash(source)
    largest.sort(reverse=True)
    return {
        "schema_version": SCHEMA_VERSION, "generated_at": now_iso(),
        "totals": {"files_scanned": len(files), "code_files": code_files, "test_files": test_files,
                   "code_loc": sum(loc.values()), "files_total_including_ignored": count},
        "languages": [{"language": k, "files": v, "loc": loc.get(k, 0)} for k, v in langs.most_common()],
        "frameworks_detected": sorted(frameworks),
        "manifests": manifests, "infrastructure": infra, "documentation": docs,
        "tests": {"files": tests[:200], "count": len(tests)},
        "env_files": envfiles, "entrypoints": sorted(set(entrypoints))[:30],
        "top_level": dict(top_level.most_common(40)),
        "largest_code_files": [{"file": f, "loc": n} for n, f in largest[:15]],
        "skipped_directories": sorted(set(skipped_dirs)),
        "binary_files": binaries[:100], "oversized_unread_files": unreadable[:100],
        "git": git, "tree_hash": th,
    }


def main() -> None:
    ap = scanner_parser("Build inventory.json")
    args = ap.parse_args()
    ws, src, _ = resolve_paths(args, "inventory")
    out = Path(args.out) if args.out else ws / "inventory.json"
    inv = build_inventory(src)
    save_json(out, inv)
    t = inv["totals"]
    print(f"[inventory] files={t['files_scanned']} code_files={t['code_files']} tests={t['test_files']} "
          f"loc={t['code_loc']} frameworks={inv['frameworks_detected']} -> {out}")


if __name__ == "__main__":
    main()
