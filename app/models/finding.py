import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class FindingSource(str, enum.Enum):
    CVE = "cve"
    KEV = "kev"
    GHSA = "ghsa"
    GITHUB_POC = "github_poc"
    ATTACK = "attack"
    CAPEC = "capec"


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("source", "external_id", name="uq_findings_source_external_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[FindingSource] = mapped_column(
        Enum(FindingSource, native_enum=False, length=20, values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    external_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str] = mapped_column(String, nullable=False, default="")

    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    raw_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Source-specific extras (CWE ids, CPE strings, GHSA severity, STIX object body, ...) live
    # here so we don't keep widening the shared columns for every new source.
    raw: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    tag_matches: Mapped[list["FindingTagMatch"]] = relationship(back_populates="finding", cascade="all, delete-orphan")


class FindingTagMatch(Base):
    __tablename__ = "finding_tag_matches"
    __table_args__ = (
        UniqueConstraint(
            "finding_id",
            "tag_id",
            "matched_keyword_id",
            "matched_technique_id",
            name="uq_finding_tag_match",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    tag_id: Mapped[int] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"), nullable=False, index=True)
    matched_keyword_id: Mapped[int | None] = mapped_column(
        ForeignKey("tag_keywords.id", ondelete="CASCADE"), nullable=True
    )
    matched_technique_id: Mapped[int | None] = mapped_column(
        ForeignKey("tag_attack_techniques.id", ondelete="CASCADE"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    finding: Mapped["Finding"] = relationship(back_populates="tag_matches")
