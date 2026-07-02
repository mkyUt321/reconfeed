from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class Tag(Base):
    __tablename__ = "tags"
    __table_args__ = (UniqueConstraint("name", "created_by_user_id", name="uq_tags_name_owner"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    is_preset: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    # Reserved for future "publish my custom tag to other users" feature. Not exposed in the
    # MVP UI or matching logic — custom tags are private to their creator until this ships.
    is_public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    keywords: Mapped[list["TagKeyword"]] = relationship(back_populates="tag", cascade="all, delete-orphan")
    attack_techniques: Mapped[list["TagAttackTechnique"]] = relationship(
        back_populates="tag", cascade="all, delete-orphan"
    )


class TagKeyword(Base):
    __tablename__ = "tag_keywords"
    __table_args__ = (UniqueConstraint("tag_id", "keyword", "created_by_user_id", name="uq_tag_keyword_owner"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    tag_id: Mapped[int] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"), nullable=False, index=True)
    keyword: Mapped[str] = mapped_column(String(255), nullable=False)
    is_preset: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tag: Mapped["Tag"] = relationship(back_populates="keywords")


class TagAttackTechnique(Base):
    __tablename__ = "tag_attack_techniques"
    __table_args__ = (
        UniqueConstraint("tag_id", "attack_technique_id", "created_by_user_id", name="uq_tag_technique_owner"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    tag_id: Mapped[int] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"), nullable=False, index=True)
    attack_technique_id: Mapped[str] = mapped_column(String(20), nullable=False)  # e.g. "T1078" or "T1558.003"
    is_preset: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    tag: Mapped["Tag"] = relationship(back_populates="attack_techniques")
