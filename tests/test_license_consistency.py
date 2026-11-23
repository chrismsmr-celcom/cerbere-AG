"""Les textes de licence, le README et l'arborescence doivent dire la même chose : Apache-2.0 partout sauf ee/."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DOCS = [
    "README.md",
    "NOTICE.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "docs/LICENSING.md",
    "docs/SELF_HOSTING.md",
]


def test_former_commercial_license_is_gone():
    assert not (ROOT / "LICENSE-COMMERCIAL.md").exists()
    leftovers = [
        str(p.relative_to(ROOT))
        for folder in ("collector", "dashboard")
        for p in (ROOT / folder).rglob("LICENSE.md")
        if "node_modules" not in p.parts
    ]
    assert leftovers == [], (
        f"per-directory license files contradict the root license: {leftovers}"
    )


def test_no_document_points_to_the_removed_license():
    offenders = [
        name
        for name in DOCS
        if "LICENSE-COMMERCIAL" in (ROOT / name).read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_readme_states_the_open_core_split():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "ee/LICENSE.md" in readme
    assert "Apache 2.0" in readme or "Apache-2.0" in readme
    # the collector and the dashboard are Apache-2.0 now: the README must not call them source-available
    assert not re.search(
        r"collector[^\n]{0,120}source-available", readme, re.IGNORECASE
    )


def test_only_ee_has_its_own_license():
    license_files = [
        str(p.relative_to(ROOT))
        for p in ROOT.rglob("LICENSE*")
        if p.is_file()
        and not {
            ".git",
            "node_modules",
            "ee",
            ".venv",
            "venv",
            ".tox",
            "__pycache__",
        }
        & set(p.relative_to(ROOT).parts)
    ]
    assert license_files == ["LICENSE"], license_files


def test_community_files_exist():
    for name in (
        "GOVERNANCE.md",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "CHANGELOG.md",
    ):
        assert (ROOT / name).is_file(), name


def test_local_markdown_links_resolve():
    link = re.compile(r"\]\((?!https?:|mailto:|#)([^)#\s]+)")
    broken = []
    for name in ("README.md", "CONTRIBUTING.md", "GOVERNANCE.md", "NOTICE.md"):
        for target in link.findall((ROOT / name).read_text(encoding="utf-8")):
            if not (ROOT / target).exists():
                broken.append(f"{name} -> {target}")
    assert broken == [], broken
