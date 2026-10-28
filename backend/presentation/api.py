from fastapi import APIRouter, Depends, Query, Request, Response, status
from hmac import compare_digest
from sqlalchemy.orm import Session

from backend.application.services import StoreService
from backend.config import Settings, get_settings
from backend.domain.entities import PaymentMethod, User
from backend.domain.errors import DomainError
from backend.infrastructure.database import get_session
from backend.infrastructure.repositories import SqlAlchemyStoreRepository
from backend.infrastructure.sessions import create_session, replace_session
from backend.presentation.dependencies import get_current_user, get_customer, require_csrf
from backend.presentation.schemas import (
    CartItemCreate,
    CartLineResponse,
    CartResponse,
    CheckoutRequest,
    OrderLineResponse,
    OrderResponse,
    ProductResponse,
    SessionResponse,
    SigninRequest,
    SignupRequest,
    UserResponse,
)


router = APIRouter(prefix="/api/v1")


def service(session: Session) -> StoreService:
    return StoreService(SqlAlchemyStoreRepository(session))


def user_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id, name=user.name, surname=user.surname, email=user.email,
        role=user.role.value, points_balance=user.points_balance,
    )


def order_response(order) -> OrderResponse:
    return OrderResponse(
        id=order.id, status=order.status, total_cents=order.total_cents,
        payment_method=order.payment_method, created_at=order.created_at,
        points_awarded=order.points_awarded,
        items=[OrderLineResponse(
            product_id=item.product_id, product_name=item.product_name,
            quantity=item.quantity, unit_price_cents=item.unit_price_cents,
        ) for item in order.items],
    )


def cart_response(items) -> CartResponse:
    lines = [CartLineResponse(
        product=ProductResponse(
            id=item.product.id, name=item.product.name, category=item.product.category,
            description=item.product.description, price_cents=item.product.price_cents,
            stock=item.product.stock,
        ), quantity=item.quantity,
        line_total_cents=item.line_total_cents,
    ) for item in items]
    return CartResponse(
        items=lines, item_count=sum(item.quantity for item in items),
        total_cents=sum(item.line_total_cents for item in items),
    )


@router.get("/products", response_model=list[ProductResponse], name="list_products")
def list_products(
    category: str | None = None,
    limit: int = Query(default=24, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
):
    return service(session).list_products(category, limit, offset)


@router.get("/products/{product_id}", response_model=ProductResponse)
def get_product(product_id: str, session: Session = Depends(get_session)):
    return service(session).get_product(product_id)


@router.get("/auth/csrf")
def get_csrf_token(
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
):
    token = request.cookies.get(settings.session_cookie_name, "")
    from backend.infrastructure.sessions import get_session_record

    current = get_session_record(session, token)
    if current is None:
        token, csrf_token = create_session(session, None, settings.session_lifetime_seconds)
        response.set_cookie(
            settings.session_cookie_name, token, max_age=settings.session_lifetime_seconds,
            httponly=True, secure=settings.secure_cookies, samesite="lax", path="/",
        )
    else:
        csrf_token = current.csrf_token
    return {"csrf_token": csrf_token}


@router.post("/auth/signup", response_model=SessionResponse, status_code=status.HTTP_201_CREATED)
def signup(
    payload: SignupRequest, request: Request, response: Response,
    session: Session = Depends(get_session), settings: Settings = Depends(get_settings),
):
    from backend.infrastructure.sessions import get_session_record

    current = get_session_record(session, request.cookies.get(settings.session_cookie_name, ""))
    if current is None or not compare_digest(request.headers.get("X-CSRF-Token", ""), current.csrf_token):
        raise HTTPException(status_code=403, detail="CSRF token is invalid.")
    store = service(session)
    user = store.signup(payload.name, payload.surname, str(payload.email), payload.password)
    token, csrf_token = replace_session(session, request.cookies.get(settings.session_cookie_name, ""), user.id, settings.session_lifetime_seconds)
    response.set_cookie(settings.session_cookie_name, token, max_age=settings.session_lifetime_seconds,
                        httponly=True, secure=settings.secure_cookies, samesite="lax", path="/")
    return SessionResponse(user=user_response(user), csrf_token=csrf_token)


@router.post("/auth/session", response_model=SessionResponse)
def signin(
    payload: SigninRequest, request: Request, response: Response,
    session: Session = Depends(get_session), settings: Settings = Depends(get_settings),
):
    from backend.infrastructure.sessions import get_session_record

    current = get_session_record(session, request.cookies.get(settings.session_cookie_name, ""))
    if current is None or not compare_digest(request.headers.get("X-CSRF-Token", ""), current.csrf_token):
        raise HTTPException(status_code=403, detail="CSRF token is invalid.")
    user = service(session).authenticate(str(payload.email), payload.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    token, csrf_token = replace_session(session, request.cookies.get(settings.session_cookie_name, ""), user.id, settings.session_lifetime_seconds)
    response.set_cookie(settings.session_cookie_name, token, max_age=settings.session_lifetime_seconds,
                        httponly=True, secure=settings.secure_cookies, samesite="lax", path="/")
    return SessionResponse(user=user_response(user), csrf_token=csrf_token)


@router.delete("/auth/session", status_code=status.HTTP_204_NO_CONTENT)
def signout(
    request: Request, response: Response,
    user: User = Depends(require_csrf), session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
):
    from backend.infrastructure.sessions import delete_session

    delete_session(session, request.cookies.get(settings.session_cookie_name, ""))
    response.delete_cookie(settings.session_cookie_name, path="/")


@router.get("/cart", response_model=CartResponse)
def get_cart(user: User = Depends(get_customer), session: Session = Depends(get_session)):
    return cart_response(service(session).get_cart(user.id))


@router.post("/cart/items", response_model=CartLineResponse, status_code=status.HTTP_201_CREATED)
def add_cart_item(
    payload: CartItemCreate, user: User = Depends(require_csrf),
    session: Session = Depends(get_session),
):
    if user.role.value != "customer":
        raise HTTPException(status_code=403, detail="Customer access required.")
    line = service(session).add_cart_item(user.id, payload.product_id, payload.quantity)
    return CartLineResponse(
        product=ProductResponse(
            id=line.product.id, name=line.product.name, category=line.product.category,
            description=line.product.description, price_cents=line.product.price_cents,
            stock=line.product.stock,
        ), quantity=line.quantity,
        line_total_cents=line.line_total_cents,
    )


@router.delete("/cart/items/{product_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_cart_item(
    product_id: str, user: User = Depends(require_csrf),
    session: Session = Depends(get_session),
):
    if user.role.value != "customer":
        raise HTTPException(status_code=403, detail="Customer access required.")
    service(session).remove_cart_item(user.id, product_id)


@router.post("/orders", response_model=OrderResponse, status_code=status.HTTP_201_CREATED)
def checkout(
    payload: CheckoutRequest, user: User = Depends(require_csrf),
    session: Session = Depends(get_session),
):
    if user.role.value != "customer":
        raise HTTPException(status_code=403, detail="Customer access required.")
    return order_response(service(session).checkout(user.id, payload.payment_method))


@router.get("/orders", response_model=list[OrderResponse])
def list_orders(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(get_customer),
    session: Session = Depends(get_session),
):
    return [order_response(order) for order in service(session).list_orders(user.id, limit, offset)]


@router.get("/orders/{order_id}", response_model=OrderResponse)
def get_order(
    order_id: str, user: User = Depends(get_customer),
    session: Session = Depends(get_session),
):
    return order_response(service(session).get_order(order_id, user.id))
