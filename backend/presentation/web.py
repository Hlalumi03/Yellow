import time
from hmac import compare_digest

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.application.services import StoreService
from backend.config import PROJECT_ROOT, Settings, get_settings
from backend.domain.entities import PaymentMethod, User
from backend.domain.errors import DomainError
from backend.infrastructure.database import get_session
from backend.infrastructure.models import CartItemModel, OrderItemModel, OrderModel, ProductModel, UserModel
from backend.infrastructure.repositories import SqlAlchemyStoreRepository
from backend.infrastructure.sessions import create_session, delete_session, get_session_record, replace_session
from backend.presentation.dependencies import get_current_user, get_customer


router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(PROJECT_ROOT / "frontend"))
PAYMENT_LABELS = {
    PaymentMethod.CASH_ON_DELIVERY: "Cash on delivery",
    PaymentMethod.BANK_TRANSFER: "Bank transfer",
    PaymentMethod.PAY_ON_PICKUP: "Pay on pickup",
}
CATEGORY_DESCRIPTIONS = {
    "Women": "Easy layers and everyday favorites, made to be worn often.",
    "Men": "Considered essentials for workdays, weekends, and everything between.",
    "Accessories": "The finishing touches that make an outfit your own.",
}
PRODUCT_IMAGES = {
    "linen-shirt": "photo-1596755094514-f87e34085b2c",
    "cotton-dress": "photo-1595777457583-95e059d581b8",
    "straight-jeans": "photo-1541099649105-f69ad21f3246",
    "knit-cardigan": "photo-1620799140408-edc6dcb6d633",
    "oxford-shirt": "photo-1602810318383-e386cc2a3ccf",
    "chino-trousers": "photo-1473966968600-fa801b869a1a",
    "crewneck-sweater": "photo-1576566588028-4147f3842f27",
    "canvas-tote": "photo-1544816155-12df9643f363",
    "leather-belt": "photo-1624222247344-550fb8b50c6f",
    "ribbed-socks": "photo-1586350977771-b3b0abab3c49",
}


def store_service(session: Session) -> StoreService:
    return StoreService(SqlAlchemyStoreRepository(session))


def csrf_for_request(request: Request, response: Response, session: Session, settings: Settings) -> str:
    token = request.cookies.get(settings.session_cookie_name, "")
    if record := get_session_record(session, token):
        return record.csrf_token
    token, csrf_token = create_session(session, None, settings.session_lifetime_seconds)
    response.set_cookie(
        settings.session_cookie_name, token, max_age=settings.session_lifetime_seconds,
        httponly=True, secure=settings.secure_cookies, samesite="lax", path="/",
    )
    return csrf_token


def check_csrf(request: Request, session: Session, settings: Settings, submitted: str) -> None:
    record = get_session_record(session, request.cookies.get(settings.session_cookie_name, ""))
    if record is None or not submitted or not compare_digest(record.csrf_token, submitted):
        raise HTTPException(status_code=403, detail="This form has expired. Reload and try again.")


def product_card(product, csrf_token: str, prefix: str) -> Markup:
    name = escape(product.name)
    image_id = PRODUCT_IMAGES.get(product.id)
    image = (
        Markup('<img loading="lazy" src="https://images.unsplash.com/{id}?auto=format&fit=crop&w=720&q=82" alt="{name}">')
        .format(id=image_id, name=name)
        if image_id else Markup("Y<span>.</span>")
    )
    disabled = "disabled" if product.stock == 0 else ""
    button_label = "Sold out" if product.stock == 0 else "Add to cart"
    return Markup(
        '<article class="store-product"><div class="product-art">{image}</div>'
        '<p class="store-category">{category}</p><h3>{name}</h3>'
        '<p class="store-description">{description}</p>'
        '<div class="store-product-foot"><strong>${price:,.2f}</strong>'
        '<form method="post" action="/cart/add">'
        '<input type="hidden" name="csrf_token" value="{csrf}">'
        '<input type="hidden" name="product_id" value="{product_id}">'
        '<label class="visually-hidden" for="{input_id}">Quantity for {name}</label>'
        '<input id="{input_id}" name="quantity" type="number" min="1" max="{stock}" value="1" {disabled}>'
        '<button type="submit" {disabled}>{button_label}</button></form></div></article>'
    ).format(
        image=image, category=escape(product.category), name=name,
        description=escape(product.description), price=product.price_cents / 100,
        csrf=escape(csrf_token), product_id=escape(product.id),
        input_id=escape(f"{prefix}-{product.id}"), stock=product.stock,
        disabled=disabled, button_label=button_label,
    )


@router.get("/style.css")
def stylesheet():
    from fastapi.responses import FileResponse

    return FileResponse(PROJECT_ROOT / "frontend" / "style.css", media_type="text/css")


@router.get("/", response_class=HTMLResponse)
def home(request: Request, session: Session = Depends(get_session), settings: Settings = Depends(get_settings)):
    record = get_session_record(session, request.cookies.get(settings.session_cookie_name, ""))
    if record and record.user_id:
        if user := store_service(session).get_user(record.user_id):
            return RedirectResponse("/account" if user.role.value == "admin" else "/shop", status_code=303)
    response = RedirectResponse("/signin", status_code=303)
    csrf_for_request(request, response, session, settings)
    return response


def render_auth_page(request: Request, title: str, template_name: str, context: dict, session: Session, settings: Settings):
    response = Response()
    csrf = csrf_for_request(request, response, session, settings)
    rendered = templates.get_template(template_name).render(csrf_token=csrf, **context)
    page = templates.TemplateResponse(request, "base.html", {"title": title, "content": Markup(rendered)})
    if response.headers.get("set-cookie"):
        page.headers.append("set-cookie", response.headers["set-cookie"])
    return page


@router.get("/signin", response_class=HTMLResponse)
def signin_page(
    request: Request, error: bool = False, session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
):
    return render_auth_page(request, "Sign in", "signin.html", {
        "notice": Markup('<div class="alert alert-danger">Email or password is incorrect.</div>') if error else Markup(""),
        "email": "",
    }, session, settings)


@router.post("/signin")
def signin_submit(
    request: Request, email: str = Form(), password: str = Form(), csrf_token: str = Form(),
    session: Session = Depends(get_session), settings: Settings = Depends(get_settings),
):
    check_csrf(request, session, settings, csrf_token)
    user = store_service(session).authenticate(email, password)
    if user is None:
        return RedirectResponse("/signin?error=true", status_code=303)
    token, _csrf = replace_session(
        session, request.cookies.get(settings.session_cookie_name, ""),
        user.id, settings.session_lifetime_seconds,
    )
    response = RedirectResponse("/account" if user.role.value == "admin" else "/shop", status_code=303)
    response.set_cookie(settings.session_cookie_name, token, max_age=settings.session_lifetime_seconds,
                        httponly=True, secure=settings.secure_cookies, samesite="lax", path="/")
    return response


@router.get("/signup", response_class=HTMLResponse)
def signup_page(
    request: Request, session: Session = Depends(get_session), settings: Settings = Depends(get_settings),
):
    return render_auth_page(request, "Sign up", "signup.html", {
        "notice": Markup(""), "name": "", "surname": "", "email": "",
    }, session, settings)


@router.post("/signup")
def signup_submit(
    request: Request, name: str = Form(), surname: str = Form(), email: str = Form(),
    password: str = Form(), csrf_token: str = Form(), session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
):
    check_csrf(request, session, settings, csrf_token)
    try:
        user = store_service(session).signup(name, surname, email, password)
    except DomainError as error:
        page = render_auth_page(request, "Sign up", "signup.html", {
            "notice": Markup('<div class="alert alert-danger">{}</div>').format(escape(error.message)),
            "name": name, "surname": surname, "email": email,
        }, session, settings)
        page.status_code = 409 if error.code == "conflict" else 400
        return page
    token, _csrf = replace_session(
        session, request.cookies.get(settings.session_cookie_name, ""),
        user.id, settings.session_lifetime_seconds,
    )
    response = RedirectResponse("/shop", status_code=303)
    response.set_cookie(settings.session_cookie_name, token, max_age=settings.session_lifetime_seconds,
                        httponly=True, secure=settings.secure_cookies, samesite="lax", path="/")
    return response


@router.get("/shop", response_class=HTMLResponse)
def shop_page(
    request: Request, user: User = Depends(get_customer), session: Session = Depends(get_session),
):
    csrf = getattr(request.state, "csrf_token", "")
    store = store_service(session)
    products = store.list_products()
    categories = []
    for index, category in enumerate(dict.fromkeys(product.category for product in products)):
        category_products = [product for product in products if product.category == category]
        cards = Markup("").join(product_card(product, csrf, f"category-{index}") for product in category_products)
        categories.append(Markup(
            '<section class="category-shelf" id="category-{index}">'
            '<div class="store-section-heading"><div><p class="store-eyebrow">SHOP THE EDIT</p>'
            '<h2>{category}</h2></div><p>{description}</p></div>'
            '<div class="category-product-row" aria-label="{category} products">{cards}</div></section>'
        ).format(index=index, category=escape(category),
                 description=escape(CATEGORY_DESCRIPTIONS.get(category, "Thoughtful pieces for your everyday wardrobe.")),
                 cards=cards))
    cart = store.get_cart(user.id)
    interests = SqlAlchemyStoreRepository(session).categories_for_customer(user.id)
    recommended = session.scalars(
        select(ProductModel).where(ProductModel.stock > 0)
        .where(ProductModel.category.in_(interests or ["Women", "Accessories"]))
        .where(~select(CartItemModel.product_id).where(
            CartItemModel.user_id == user.id, CartItemModel.product_id == ProductModel.id,
        ).exists())
        .where(~select(OrderItemModel.product_id).join(OrderModel, OrderModel.id == OrderItemModel.order_id)
               .where(OrderModel.user_id == user.id, OrderItemModel.product_id == ProductModel.id).exists())
        .order_by(ProductModel.name).limit(4)
    ).all()
    recommendation_cards = Markup("").join(product_card(row, csrf, "recommended") for row in recommended)
    notice = Markup("")
    order_id = request.query_params.get("order", "")
    if order_id.startswith("YL-"):
        if confirmed := SqlAlchemyStoreRepository(session).get_order(order_id, user.id):
            notice = Markup('<div class="alert alert-success">Order {} was received. The store team will contact you about payment and fulfillment.</div>').format(escape(confirmed.id))
    elif request.query_params.get("added") == "1":
        notice = Markup('<div class="alert alert-success">Your order is confirmed. Thank you for shopping with Yellow.</div>')
    return templates.TemplateResponse(request, "store.html", {
        "name": user.name, "csrf_token": csrf, "points_balance": str(user.points_balance),
        "cart_count": str(sum(item.quantity for item in cart)), "notice": notice,
        "category_collections": Markup("").join(categories),
        "recommendation_cards": recommendation_cards or Markup('<p class="empty-recommendations">More new pieces are on the way.</p>'),
        "recommendation_note": "Picked from categories in your cart and past orders." if interests else "Start exploring this season’s favorites.",
    })


@router.get("/cart", response_class=HTMLResponse)
def cart_page(request: Request, user: User = Depends(get_customer), session: Session = Depends(get_session)):
    csrf = getattr(request.state, "csrf_token", "")
    items = store_service(session).get_cart(user.id)
    rows = Markup("").join(Markup(
        "<tr><td>{name}</td><td>{quantity}</td><td>${price:,.2f}</td><td>${total:,.2f}</td></tr>"
    ).format(name=escape(item.product.name), quantity=item.quantity,
             price=item.product.price_cents / 100, total=item.line_total_cents / 100) for item in items)
    options = Markup("").join(Markup('<option value="{value}">{label}</option>').format(
        value=method.value, label=escape(label)) for method, label in PAYMENT_LABELS.items())
    cart_error = request.query_params.get("error", "")
    messages = {
        "empty_cart": "Your cart is empty.",
        "insufficient_stock": "That quantity is no longer available. Review your cart and try again.",
        "not_found": "That item is no longer available.",
    }
    notice = Markup("")
    if request.query_params.get("added") == "1":
        notice = Markup('<div class="alert alert-success">Cart updated. Your items and total are shown below.</div>')
    elif cart_error in messages:
        notice = Markup('<div class="alert alert-warning">{}</div>').format(escape(messages[cart_error]))
    return templates.TemplateResponse(request, "cart.html", {
        "name": user.name, "csrf_token": csrf, "cart_count": str(sum(item.quantity for item in items)),
        "points_balance": str(user.points_balance), "payment_options": options,
        "notice": notice, "cart_rows": rows,
        "cart_total": f"${sum(i.line_total_cents for i in items) / 100:,.2f}",
        "cart_item_count": str(sum(item.quantity for item in items)),
        "cart_empty": Markup("") if items else Markup('<p class="empty-cart">Your cart is empty. <a href="/shop">Browse the store</a>.</p>'),
        "checkout_disabled": "" if items else "disabled",
    })


@router.post("/cart/add")
def cart_add(
    request: Request, product_id: str = Form(), quantity: int = Form(), csrf_token: str = Form(),
    user: User = Depends(get_customer), session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
):
    check_csrf(request, session, settings, csrf_token)
    try:
        store_service(session).add_cart_item(user.id, product_id, quantity)
    except DomainError as error:
        return RedirectResponse(f"/cart?error={error.code}", status_code=303)
    return RedirectResponse("/cart?added=1", status_code=303)


@router.post("/checkout")
def checkout_submit(
    request: Request, payment_method: PaymentMethod = Form(), csrf_token: str = Form(),
    user: User = Depends(get_customer), session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
):
    check_csrf(request, session, settings, csrf_token)
    try:
        order = store_service(session).checkout(user.id, payment_method)
    except DomainError as error:
        return RedirectResponse(f"/cart?error={error.code}", status_code=303)
    return RedirectResponse(f"/shop?order={order.id}", status_code=303)


@router.post("/logout")
def logout(
    request: Request, csrf_token: str = Form(), user: User = Depends(get_current_user),
    session: Session = Depends(get_session), settings: Settings = Depends(get_settings),
):
    check_csrf(request, session, settings, csrf_token)
    delete_session(session, request.cookies.get(settings.session_cookie_name, ""))
    response = RedirectResponse("/signin", status_code=303)
    response.delete_cookie(settings.session_cookie_name, path="/")
    return response


@router.get("/account", response_class=HTMLResponse)
def account_page(request: Request, user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    if user.role.value != "admin":
        return RedirectResponse("/shop", status_code=303)
    order_count, revenue = session.execute(select(
        func.count(OrderModel.id), func.coalesce(func.sum(OrderModel.total_cents), 0)
    )).one()
    customer_count = session.scalar(select(func.count(UserModel.id)).where(UserModel.role == "customer")) or 0
    product_count = session.scalar(select(func.count(ProductModel.id))) or 0
    orders = session.scalars(select(OrderModel).order_by(OrderModel.created_at.desc()).limit(12)).all()
    order_rows = []
    for order in orders:
        customer = session.get(UserModel, order.user_id)
        names = session.scalars(select(OrderItemModel.product_name).where(OrderItemModel.order_id == order.id)).all()
        lines = Markup(", ").join(escape(name) for name in names)
        order_rows.append(Markup(
            '<tr><td><strong>{id}</strong><small>{date}</small></td>'
            '<td>{customer}<small>{email}</small></td><td>{items}</td><td>${total:,.2f}</td>'
            '<td>{payment}<small>{points} points earned</small></td><td><span class="order-status">{status}</span></td></tr>'
        ).format(id=escape(order.id), date=time.strftime("%b %d, %Y", time.localtime(order.created_at)),
                 customer=escape(f"{customer.name} {customer.surname}" if customer else "Unknown"),
                 email=escape(customer.email if customer else ""), items=lines,
                 total=order.total_cents / 100, payment=PAYMENT_LABELS[PaymentMethod(order.payment_method)],
                 points=order.points_awarded, status=escape(order.status)))
    customers = session.scalars(select(UserModel).where(UserModel.role == "customer").order_by(UserModel.created_at.desc()).limit(8)).all()
    customer_rows = Markup("").join(Markup("<tr><td>{name}</td><td>{email}</td><td>{date}</td><td>{points}</td></tr>").format(
        name=escape(f"{item.name} {item.surname}"), email=escape(item.email),
        date=time.strftime("%b %d, %Y", time.localtime(item.created_at)), points=item.points_balance) for item in customers)
    context = {
        "csrf_token": getattr(request.state, "csrf_token", ""), "name": user.name,
        "initial": user.name[:1].upper(), "order_count": str(order_count),
        "revenue": f"${revenue / 100:,.2f}", "customer_count": str(customer_count),
        "product_count": str(product_count),
        "order_rows": Markup("").join(order_rows) or Markup('<tr><td colspan="6" class="empty-table">No customer orders yet.</td></tr>'),
        "customer_rows": customer_rows or Markup('<tr><td colspan="4" class="empty-table">No customer accounts yet.</td></tr>'),
    }
    return templates.TemplateResponse(request, "home.html", context)
