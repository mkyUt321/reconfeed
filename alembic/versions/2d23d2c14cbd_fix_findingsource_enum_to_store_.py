"""fix findingsource enum to store lowercase values

Revision ID: 2d23d2c14cbd
Revises: 0c438040e6c0
Create Date: 2026-07-03 01:36:45.222622

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2d23d2c14cbd'
down_revision: Union[str, None] = '0c438040e6c0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # FindingSource previously persisted the Python enum *member name* (e.g. "CVE") instead of
    # its .value ("cve"). The model now sets values_callable to store lowercase values matching
    # the plan's schema spec; fix up any rows written under the old behavior.
    op.execute("UPDATE findings SET source = lower(source) WHERE source != lower(source)")


def downgrade() -> None:
    op.execute("UPDATE findings SET source = upper(source) WHERE source != upper(source)")
