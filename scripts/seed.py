"""Idempotently upsert seed/preset_tags.yaml into the DB.

Only touches rows with is_preset=True / created_by_user_id=None. Never modifies rows a user
added through the UI, even if they're attached to a preset tag.

Usage: python scripts/seed.py
"""

import pathlib
import sys

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app.db import SessionLocal  # noqa: E402
from app.models import Tag, TagAttackTechnique, TagKeyword  # noqa: E402

SEED_FILE = pathlib.Path(__file__).resolve().parent.parent / "seed" / "preset_tags.yaml"


def main() -> None:
    with open(SEED_FILE, encoding="utf-8") as f:
        entries = yaml.safe_load(f)

    db = SessionLocal()
    created_tags = updated_keywords = removed_keywords = 0
    created_techniques = removed_techniques = 0

    try:
        for entry in entries:
            name = entry["name"]
            tag = db.query(Tag).filter(Tag.name == name, Tag.is_preset.is_(True)).first()
            if tag is None:
                tag = Tag(name=name, is_preset=True, created_by_user_id=None)
                db.add(tag)
                db.flush()
                created_tags += 1

            wanted_keywords = {k.strip().lower() for k in entry.get("keywords", [])}
            existing_kw_rows = (
                db.query(TagKeyword)
                .filter(TagKeyword.tag_id == tag.id, TagKeyword.is_preset.is_(True))
                .all()
            )
            existing_kw = {row.keyword for row in existing_kw_rows}

            for kw in wanted_keywords - existing_kw:
                db.add(TagKeyword(tag_id=tag.id, keyword=kw, is_preset=True, created_by_user_id=None))
                updated_keywords += 1

            for row in existing_kw_rows:
                if row.keyword not in wanted_keywords:
                    db.delete(row)
                    removed_keywords += 1

            wanted_techniques = {t.strip().upper() for t in entry.get("attack_techniques", [])}
            existing_tech_rows = (
                db.query(TagAttackTechnique)
                .filter(TagAttackTechnique.tag_id == tag.id, TagAttackTechnique.is_preset.is_(True))
                .all()
            )
            existing_tech = {row.attack_technique_id for row in existing_tech_rows}

            for tech in wanted_techniques - existing_tech:
                db.add(
                    TagAttackTechnique(
                        tag_id=tag.id, attack_technique_id=tech, is_preset=True, created_by_user_id=None
                    )
                )
                created_techniques += 1

            for row in existing_tech_rows:
                if row.attack_technique_id not in wanted_techniques:
                    db.delete(row)
                    removed_techniques += 1

        db.commit()
    finally:
        db.close()

    print(
        f"tags created={created_tags}, keywords added={updated_keywords} removed={removed_keywords}, "
        f"attack techniques added={created_techniques} removed={removed_techniques}"
    )


if __name__ == "__main__":
    main()
