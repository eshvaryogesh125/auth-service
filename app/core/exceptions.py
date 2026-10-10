class AuthError(ValueError):
    """Base class for auth service validation failures."""


class TenantNotFoundError(AuthError):
    pass


class EmailAlreadyExistsError(AuthError):
    pass


class InvalidCredentialsError(AuthError):
    pass


class EmailNotVerifiedError(AuthError):
    pass


class AccountDeactivatedError(AuthError):
    pass


class AccountLockedError(AuthError):
    pass


class InvalidTokenError(AuthError):
    pass


class TokenExpiredError(InvalidTokenError):
    pass


class TokenReuseDetectedError(InvalidTokenError):
    pass


class InvalidCurrentPasswordError(AuthError):
    pass


class InvalidOrExpiredTokenError(AuthError):
    pass


class UserNotFoundError(AuthError):
    pass
