from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    notify_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notify_frequency: Mapped[str] = mapped_column(String(20), nullable=False, default="daily")

    cvss_filter_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Comma-separated CVSS Attack Vector values to require when the filter is enabled, e.g. "NETWORK,ADJACENT_NETWORK"
    cvss_allowed_attack_vectors: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    watchlists: Mapped[list["Watchlist"]] = relationship(back_populates="user", cascade="all, delete-orphan")

    def notification_target(self) -> str:
        return self.notify_email or self.email
