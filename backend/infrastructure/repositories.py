import secrets
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from backend.domain.entities import (
    CartLine,
    Order,
    OrderLine,
    PaymentMethod,
    Product,
    User,
    UserRole,
)
from backend.domain.errors import ConflictError, DomainError, NotFoundError
from backend.infrastructure.models import (
    CartItemModel,
    OrderItemModel,
    OrderModel,
    ProductModel,
    UserModel,
)


def to_product(model: ProductModel) -> Product:
    return Product(model.id, model.name, model.category, model.description, model.price_cents, model.stock)


def to_user(model: UserModel) -> User:
    return User(
        model.id, model.name, model.surname, model.email, model.password_hash,
        model.created_at, UserRole(model.role), model.points_balance,
    )


def to_order(model: OrderModel) -> Order:
    return Order(
        model.id, model.user_id, model.total_cents, PaymentMethod(model.payment_method),
        model.created_at, model.status, model.points_awarded,
        tuple(OrderLine(item.product_id, item.product_name, item.quantity, item.unit_price_cents)
              for item in model.items),
    )


class SqlAlchemyStoreRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    @contextmanager
    def transaction(self) -> Iterator[None]:
        try:
            yield
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise

    def list_products(self, category: str | None = None, limit: int = 24, offset: int = 0) -> list[Product]:
        statement = select(ProductModel).order_by(ProductModel.category, ProductModel.name)
        if category:
            statement = statement.where(ProductModel.category == category)
        statement = statement.limit(limit).offset(offset)
        return [to_product(row) for row in self.session.scalars(statement)]

    def get_product(self, product_id: str) -> Product | None:
        model = self.session.get(ProductModel, product_id)
        return to_product(model) if model else None

    def get_user(self, user_id: str) -> User | None:
        model = self.session.get(UserModel, user_id)
        return to_user(model) if model else None

    def get_user_by_email(self, email: str) -> User | None:
        model = self.session.scalar(select(UserModel).where(UserModel.email == email))
        return to_user(model) if model else None

    def create_user(self, user: User) -> None:
        self.session.add(UserModel(
            id=user.id, name=user.name, surname=user.surname, email=user.email,
            password_hash=user.password_hash, created_at=user.created_at,
            role=user.role.value, points_balance=user.points_balance,
        ))
        try:
            self.session.flush()
        except Exception as error:
            from sqlalchemy.exc import IntegrityError
            if isinstance(error, IntegrityError):
                raise ConflictError("An account with that email already exists.") from error
            raise

    def get_cart(self, user_id: str) -> list[CartLine]:
        rows = self.session.scalars(
            select(CartItemModel).options(joinedload(CartItemModel.product))
            .where(CartItemModel.user_id == user_id)
            .order_by(CartItemModel.product_id)
        )
        return [CartLine(to_product(row.product), row.quantity) for row in rows]

    def add_cart_item(self, user_id: str, product_id: str, quantity: int) -> CartLine:
        product = self.session.scalar(
            select(ProductModel).where(ProductModel.id == product_id).with_for_update()
        )
        if product is None:
            raise NotFoundError("Product")
        line = self.session.get(CartItemModel, (user_id, product_id))
        total_quantity = quantity + (line.quantity if line else 0)
        if total_quantity > product.stock:
            raise DomainError("The selected quantity is not available.", "insufficient_stock")
        if line:
            line.quantity = total_quantity
        else:
            line = CartItemModel(user_id=user_id, product_id=product_id, quantity=total_quantity)
            self.session.add(line)
        self.session.flush()
        return CartLine(to_product(product), total_quantity)

    def remove_cart_item(self, user_id: str, product_id: str) -> None:
        line = self.session.get(CartItemModel, (user_id, product_id))
        if line is None:
            raise NotFoundError("Cart item")
        self.session.delete(line)

    def create_order(self, user_id: str, method: PaymentMethod, now: int) -> Order:
        user = self.session.get(UserModel, user_id)
        if user is None:
            raise NotFoundError("Customer")
        rows = list(self.session.scalars(
            select(CartItemModel).options(joinedload(CartItemModel.product))
            .where(CartItemModel.user_id == user_id).with_for_update()
        ))
        if not rows:
            raise DomainError("Your cart is empty.", "empty_cart")
        for row in rows:
            if row.quantity > row.product.stock:
                raise DomainError("Some items are no longer available in the requested quantity.", "insufficient_stock")

        total_cents = sum(row.product.price_cents * row.quantity for row in rows)
        points_awarded = total_cents // 100
        order = OrderModel(
            id="YL-" + secrets.token_hex(6).upper(), user_id=user_id,
            total_cents=total_cents, status="New", created_at=now,
            payment_method=method.value, points_awarded=points_awarded,
        )
        order.items = [
            OrderItemModel(
                product_id=row.product_id, product_name=row.product.name,
                quantity=row.quantity, unit_price_cents=row.product.price_cents,
            ) for row in rows
        ]
        for row in rows:
            row.product.stock -= row.quantity
        user.points_balance += points_awarded
        self.session.add(order)
        for row in rows:
            self.session.delete(row)
        self.session.flush()
        return to_order(order)

    def get_order(self, order_id: str, user_id: str) -> Order | None:
        model = self.session.execute(
            select(OrderModel).options(joinedload(OrderModel.items))
            .where(OrderModel.id == order_id, OrderModel.user_id == user_id)
        ).unique().scalar_one_or_none()
        return to_order(model) if model else None

    def list_orders(self, user_id: str, limit: int, offset: int) -> list[Order]:
        rows = self.session.execute(
            select(OrderModel).options(joinedload(OrderModel.items))
            .where(OrderModel.user_id == user_id)
            .order_by(OrderModel.created_at.desc(), OrderModel.id.desc())
            .limit(limit).offset(offset)
        ).unique().scalars()
        return [to_order(row) for row in rows]

    def categories_for_customer(self, user_id: str) -> list[str]:
        from sqlalchemy import func

        cart_categories = select(ProductModel.category.label("category")).join(
            CartItemModel, CartItemModel.product_id == ProductModel.id
        ).where(CartItemModel.user_id == user_id)
        order_categories = select(ProductModel.category.label("category")).join(
            OrderItemModel, OrderItemModel.product_id == ProductModel.id
        ).join(OrderModel, OrderModel.id == OrderItemModel.order_id).where(OrderModel.user_id == user_id)
        categories = cart_categories.union_all(order_categories).subquery()
        return list(self.session.scalars(
            select(categories.c.category).group_by(categories.c.category)
            .order_by(func.count().desc(), categories.c.category)
        ))
