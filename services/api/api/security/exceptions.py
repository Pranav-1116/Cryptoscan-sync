class AuthenticationError(Exception):
    def __init__(self, message: str = "Authentication failed"):
        self.message = message
        super().__init__(message)


class ValidationError(Exception):
    def __init__(self, message: str, errors: list | None = None):
        self.message = message
        self.errors = errors or []
        super().__init__(message)
