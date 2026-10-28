"""Create the store schema and seed the apparel catalog."""

from alembic import op
from sqlalchemy import Column, Integer, String, inspect, select, text

from backend.infrastructure.database import Base
from backend.infrastructure import models  # noqa: F401


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


PRODUCTS = [
    ("linen-shirt", "Relaxed linen shirt", "Women", "Breathable linen with a relaxed everyday fit.", 6800, 24),
    ("cotton-dress", "Sunday cotton dress", "Women", "A soft cotton dress made for easy afternoons.", 8400, 18),
    ("straight-jeans", "Everyday straight jeans", "Women", "Mid-rise denim with a clean straight leg.", 9200, 20),
    ("knit-cardigan", "Soft knit cardigan", "Women", "A lightweight layer in a comfortable cotton blend.", 7600, 16),
    ("oxford-shirt", "Classic oxford shirt", "Men", "A versatile cotton shirt with a timeless collar.", 7200, 22),
    ("chino-trousers", "Relaxed chino trousers", "Men", "An easy tapered trouser for daily wear.", 7900, 20),
    ("crewneck-sweater", "Merino crewneck sweater", "Men", "Fine-gauge merino wool with a neat crew neckline.", 11800, 14),
    ("canvas-tote", "Everyday canvas tote", "Accessories", "A sturdy carryall for errands and weekends.", 2800, 40),
    ("leather-belt", "Minimal leather belt", "Accessories", "A simple leather belt with a brushed metal buckle.", 4600, 25),
    ("ribbed-socks", "Ribbed cotton socks", "Accessories", "A soft, mid-calf pair made from combed cotton.", 1200, 60),
]


def _columns(table_name: str) -> set[str]:
    return {column["name"] for column in inspect(op.get_bind()).get_columns(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind, checkfirst=True)
    existing_tables = set(inspect(bind).get_table_names())
    if "users" in existing_tables:
        columns = _columns("users")
        if "role" not in columns:
            op.add_column("users", Column("role", String(20), nullable=False, server_default="customer"))
        if "points_balance" not in columns:
            op.add_column("users", Column("points_balance", Integer, nullable=False, server_default="0"))
    if "orders" in existing_tables:
        columns = _columns("orders")
        if "payment_method" not in columns:
            op.add_column("orders", Column("payment_method", String(32), nullable=False, server_default="cash_on_delivery"))
            bind.execute(text("UPDATE orders SET payment_method = 'cash_on_delivery'"))
        if "points_awarded" not in columns:
            op.add_column("orders", Column("points_awarded", Integer, nullable=False, server_default="0"))
    existing_ids = set(bind.execute(select(models.ProductModel.id)).scalars())
    for row in PRODUCTS:
        if row[0] not in existing_ids:
            bind.execute(models.ProductModel.__table__.insert().values(
                id=row[0], name=row[1], category=row[2], description=row[3],
                price_cents=row[4], stock=row[5],
            ))


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
