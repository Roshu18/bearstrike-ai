"""Skill document loader for BearStrike AI.

Skills are markdown playbooks under /skills that guide AI tool selection.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parents[1]
SKILLS_DIR = BASE_DIR / "skills"


@dataclass
class SkillDoc:
    name: str
    path: Path
    description: str
    content: str = ""


_SKILLS_CACHE_KEY: Tuple[Tuple[str, int, int], ...] | None = None
_SKILLS_CACHE_DOCS_FULL: List[SkillDoc] | None = None
_SKILLS_CACHE_DOCS_META: List[SkillDoc] | None = None


def _parse_front_matter(md_text: str) -> Dict[str, str]:
    lines = md_text.splitlines()
    meta: Dict[str, str] = {}

    if len(lines) < 3 or lines[0].strip() != "---":
        return meta

    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "---":
            break
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        meta[key.strip().lower()] = value.strip().strip('"')

    return meta


def _list_skill_files(skills_dir: Path) -> List[Path]:
    if not skills_dir.exists():
        return []
    return sorted(skills_dir.glob("*/SKILL.md"))


def _build_cache_key(skill_files: List[Path]) -> Tuple[Tuple[str, int, int], ...]:
    entries: List[Tuple[str, int, int]] = []
    for skill_file in skill_files:
        try:
            stat = skill_file.stat()
        except OSError:
            continue
        entries.append((str(skill_file), int(stat.st_mtime_ns), int(stat.st_size)))
    return tuple(entries)


def _read_head(path: Path, max_chars: int = 16384) -> Optional[str]:
    try:
        with path.open("r", encoding="utf-8-sig") as file:
            return file.read(max_chars)
    except OSError:
        return None


def _read_full(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8-sig")
    except OSError:
        return None


def load_skill_documents(
    skills_dir: Path = SKILLS_DIR,
    force_reload: bool = False,
    include_content: bool = True,
) -> List[SkillDoc]:
    global _SKILLS_CACHE_KEY, _SKILLS_CACHE_DOCS_FULL, _SKILLS_CACHE_DOCS_META

    skill_files = _list_skill_files(skills_dir)
    cache_key = _build_cache_key(skill_files)

    if cache_key != _SKILLS_CACHE_KEY:
        _SKILLS_CACHE_KEY = cache_key
        _SKILLS_CACHE_DOCS_FULL = None
        _SKILLS_CACHE_DOCS_META = None

    if not force_reload:
        if include_content and _SKILLS_CACHE_DOCS_FULL is not None:
            return list(_SKILLS_CACHE_DOCS_FULL)
        if not include_content and _SKILLS_CACHE_DOCS_META is not None:
            return list(_SKILLS_CACHE_DOCS_META)

    docs: List[SkillDoc] = []
    for skill_file in skill_files:
        if include_content:
            text = _read_full(skill_file)
            if text is None:
                continue
            meta_source = text
            content = text.strip()
        else:
            head = _read_head(skill_file)
            if head is None:
                continue
            meta_source = head
            content = ""

        meta = _parse_front_matter(meta_source)
        docs.append(
            SkillDoc(
                name=meta.get("name", skill_file.parent.name),
                description=meta.get("description", ""),
                path=skill_file,
                content=content,
            )
        )

    if include_content:
        _SKILLS_CACHE_DOCS_FULL = list(docs)
    else:
        _SKILLS_CACHE_DOCS_META = list(docs)

    return docs


def list_skills() -> List[Dict[str, str]]:
    skills = load_skill_documents(include_content=False)
    return [
        {
            "name": skill.name,
            "description": skill.description,
            "path": str(skill.path),
        }
        for skill in skills
    ]


def build_skill_lookup(include_content: bool = False) -> Dict[str, SkillDoc]:
    lookup: Dict[str, SkillDoc] = {}
    for skill in load_skill_documents(include_content=include_content):
        canonical = skill.name.strip().lower() or skill.path.parent.name.lower()
        folder_name = skill.path.parent.name.lower()
        aliases = {canonical, folder_name}
        for alias in aliases:
            lookup[alias] = skill
    return lookup


def get_skill_content(name: str, max_chars: int | None = None) -> Optional[str]:
    normalized = name.strip().lower()
    doc = build_skill_lookup(include_content=False).get(normalized)
    if doc is None:
        return None

    try:
        with doc.path.open("r", encoding="utf-8-sig") as file:
            if max_chars is not None and max_chars > 0:
                return file.read(max_chars).strip()
            return file.read().strip()
    except OSError:
        return None


def build_skill_context(max_chars: int = 12000) -> str:
    """Return a compact multi-skill context string for LLM prompts."""
    chunks: List[str] = []
    total = 0

    for skill in load_skill_documents(include_content=True):
        block = (
            f"## Skill: {skill.name}\n"
            f"Description: {skill.description or 'N/A'}\n"
            f"Path: {skill.path}\n\n"
            f"{skill.content}\n"
        )
        if total + len(block) > max_chars:
            break
        chunks.append(block)
        total += len(block)

    return "\n".join(chunks).strip()