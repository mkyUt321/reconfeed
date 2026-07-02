from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class FetchState(Base):
    """Per-source incremental-fetch cursor (e.g. NVD's lastModEndDate, GHSA's last seen
    updatedAt). Sources that fetch a small/full snapshot each run (KEV, EPSS, ATT&CK, CAPEC)
    don't need a row here — they diff against the findings table directly."""

    __tablename__ = "fetch_state"

    source: Mapped[str] = mapped_column(String(50), primary_key=True)
    cursor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
