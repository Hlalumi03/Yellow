import hashlib
import hmac
import re
import secrets
import time

from backend.application.ports import StoreRepository
from backend.domain.entities import Order, PaymentMethod, Product, User
from backend.domain.errors import ConflictError, DomainError, NotFoundError


PASSWORD_ITERATIONS = 310_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ITERATIONS)
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, expected_hex = stored_hash.split(":", 1)
        salt, expected = bytes.fromhex(salt_hex), bytes.fromhex(expected_hex)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ITERATIONS)
    return hmac.compare_digest(actual, expected)


class StoreService:
    def __init__(self, repository: StoreRepository) -> None:
        self.repository = repository

    def list_products(self, category: str | None = None, limit: int = 24, offset: int = 0) -> list[Product]:
        return self.repository.list_products(category, limit, offset)

    def get_product(self, product_id: str) -> Product:
        product = self.repository.get_product(product_id)
        if product is None:
            raise NotFoundError("Product")
        return product

    def get_cart(self, user_id: str):
        return self.repository.get_cart(user_id)

    def add_cart_item(self, user_id: str, product_id: str, quantity: int):
        if quantity < 1:
            raise DomainError("Quantity must be at least one.", "invalid_quantity")
        with self.repository.transaction():
            return self.repository.add_cart_item(user_id, product_id, quantity)

    def remove_cart_item(self, user_id: str, product_id: str) -> None:
        with self.repository.transaction():
            self.repository.remove_cart_item(user_id, product_id)

    def checkout(self, user_id: str, method: PaymentMethod) -> Order:
        with self.repository.transaction():
            return self.repository.create_order(user_id, method, int(time.time()))

    def get_order(self, order_id: str, user_id: str) -> Order:
        order = self.repository.get_order(order_id, user_id)
        if order is None:
            raise NotFoundError("Order")
        return order

    def list_orders(self, user_id: str, limit: int = 20, offset: int = 0) -> list[Order]:
        return self.repository.list_orders(user_id, limit, offset)

    def signup(self, name: str, surname: str, email: str, password: str) -> User:
        name, surname, email = name.strip(), surname.strip(), email.strip().lower()
        if not name or len(name) > 80 or not surname or len(surname) > 80:
            raise DomainError("Name and surname are required and must be under 80 characters.", "invalid_user")
        if len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise DomainError("Enter a valid email address.", "invalid_email")
        if len(password) < 8 or len(password) > 1024:
            raise DomainError("Password must be between 8 and 1024 characters.", "invalid_password")
        if self.repository.get_user_by_email(email):
            raise ConflictError("An account with that email already exists.")
        user = User(
            id=secrets.token_urlsafe(16), name=name, surname=surname, email=email,
            password_hash=hash_password(password), created_at=int(time.time()),
        )
        with self.repository.transaction():
            self.repository.create_user(user)
        return user

    def authenticate(self, email: str, password: str) -> User | None:
        user = self.repository.get_user_by_email(email.strip().lower())
        if user is None:
            verify_password(password[:1024], DUMMY_PASSWORD_HASH)
            return None
        if len(password) > 1024 or not verify_password(password, user.password_hash):
            return None
        return user

    def get_user(self, user_id: str) -> User | None:
        return self.repository.get_user(user_id)


DUMMY_PASSWORD_HASH = hash_password("not-a-real-user-password")
