from dataclasses import dataclass
from enum import StrEnum


class UserRole(StrEnum):
    CUSTOMER = "customer"
    ADMIN = "admin"


class PaymentMethod(StrEnum):
    CASH_ON_DELIVERY = "cash_on_delivery"
    BANK_TRANSFER = "bank_transfer"
    PAY_ON_PICKUP = "pay_on_pickup"


@dataclass(frozen=True, slots=True)
class User:
    id: str
    name: str
    surname: str
    email: str
    password_hash: str
    created_at: int
    role: UserRole = UserRole.CUSTOMER
    points_balance: int = 0


@dataclass(frozen=True, slots=True)
class Product:
    id: str
    name: str
    category: str
    description: str
    price_cents: int
    stock: int


@dataclass(frozen=True, slots=True)
class CartLine:
    product: Product
    quantity: int

    @property
    def line_total_cents(self) -> int:
        return self.product.price_cents * self.quantity


@dataclass(frozen=True, slots=True)
class OrderLine:
    product_id: str
    product_name: str
    quantity: int
    unit_price_cents: int


@dataclass(frozen=True, slots=True)
class Order:
    id: str
    user_id: str
    total_cents: int
    payment_method: PaymentMethod
    created_at: int
    status: str
    points_awarded: int
    items: tuple[OrderLine, ...]
