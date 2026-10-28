from sqlalchemy import CheckConstraint, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.infrastructure.database import Base


class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    surname: Mapped[str] = mapped_column(String(80), nullable=False)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[int] = mapped_column(Integer, nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="customer")
    points_balance: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cart_items: Mapped[list["CartItemModel"]] = relationship(cascade="all, delete-orphan")


class SessionModel(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    csrf_token: Mapped[str] = mapped_column(String(128), nullable=False)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    expires_at: Mapped[int] = mapped_column(Integer, nullable=False, index=True)


class ProductModel(Base):
    __tablename__ = "products"
    __table_args__ = (CheckConstraint("price_cents >= 0"), CheckConstraint("stock >= 0"))

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    description: Mapped[str] = mapped_column(String(500), nullable=False)
    price_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    stock: Mapped[int] = mapped_column(Integer, nullable=False)


class CartItemModel(Base):
    __tablename__ = "cart_items"
    __table_args__ = (CheckConstraint("quantity > 0"),)

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id"), primary_key=True)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    product: Mapped[ProductModel] = relationship()


class OrderModel(Base):
    __tablename__ = "orders"
    __table_args__ = (CheckConstraint("total_cents >= 0"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    total_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="New")
    created_at: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    payment_method: Mapped[str] = mapped_column(String(32), nullable=False)
    points_awarded: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    items: Mapped[list["OrderItemModel"]] = relationship(cascade="all, delete-orphan")


class OrderItemModel(Base):
    __tablename__ = "order_items"
    __table_args__ = (CheckConstraint("quantity > 0"), CheckConstraint("unit_price_cents >= 0"))

    order_id: Mapped[str] = mapped_column(ForeignKey("orders.id", ondelete="CASCADE"), primary_key=True)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id"), primary_key=True)
    product_name: Mapped[str] = mapped_column(String(160), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    unit_price_cents: Mapped[int] = mapped_column(Integer, nullable=False)
