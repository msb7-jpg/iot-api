from passlib.context import CryptContext
"""
This module is used to decouple the auth service from user service
it serves as an interface between these two services
"""
# Use a scheme that doesn't require the external 'bcrypt' C-extension to avoid
# runtime issues in environments where the 'bcrypt' package is missing or incompatible.
# pbkdf2_sha256 is a secure, widely supported scheme implemented in pure Python
# via passlib and avoids bcrypt's 72-byte password limit.
password_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return password_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_context.verify(plain_password, hashed_password)
