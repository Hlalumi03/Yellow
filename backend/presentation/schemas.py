from pydantic import BaseModel, ConfigDict, EmailStr, Field

from backend.domain.entities import PaymentMethod


class ProductResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    category: str
    description: str
    price_cents: int
    stock: int


class CartItemCreate(BaseModel):
    product_id: str = Field(min_length=1, max_length=64)
    quantity: int = Field(ge=1, le=100)


class CartLineResponse(BaseModel):
    product: ProductResponse
    quantity: int
    line_total_cents: int


class CartResponse(BaseModel):
    items: list[CartLineResponse]
    item_count: int
    total_cents: int


class CheckoutRequest(BaseModel):
    payment_method: PaymentMethod


class OrderLineResponse(BaseModel):
    product_id: str
    product_name: str
    quantity: int
    unit_price_cents: int


class OrderResponse(BaseModel):
    id: str
    status: str
    total_cents: int
    payment_method: PaymentMethod
    created_at: int
    points_awarded: int
    items: list[OrderLineResponse]


class SignupRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    surname: str = Field(min_length=1, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8, max_length=1024)


class SigninRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=1024)


class UserResponse(BaseModel):
    id: str
    name: str
    surname: str
    email: EmailStr
    role: str
    points_balance: int


class SessionResponse(BaseModel):
    user: UserResponse
    csrf_token: str


class ErrorResponse(BaseModel):
    detail: str
    code: str | None = None
