class DomainError(Exception):
    def __init__(self, message: str, code: str = "business_rule_violation") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class NotFoundError(DomainError):
    def __init__(self, resource: str) -> None:
        super().__init__(f"{resource} was not found.", "not_found")


class ConflictError(DomainError):
    def __init__(self, message: str) -> None:
        super().__init__(message, "conflict")


class AuthenticationError(DomainError):
    def __init__(self, message: str = "Authentication is required.") -> None:
        super().__init__(message, "unauthorized")
