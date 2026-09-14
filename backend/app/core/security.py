"""Primitivas de segurança: hashing de palavras-passe e tokens de sessão.

Decisões:

* **Argon2id** para palavras-passe. É o vencedor da Password Hashing Competition
  e a recomendação actual da OWASP; ao contrário do bcrypt não trunca a entrada
  aos 72 bytes e é resistente a ataques com hardware dedicado.
* **Access token JWT de vida curta + refresh token opaco persistido.** O JWT
  permite validar pedidos sem ir à base de dados; o refresh token é guardado
  apenas como hash SHA-256, de modo que uma leitura não autorizada da tabela de
  sessões não permite personificar ninguém. É isto que torna a revogação real -
  um JWT puro não pode ser revogado antes de expirar.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Literal

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import settings

# Parâmetros acima dos mínimos da OWASP (19 MiB, t=2, p=1).
_hasher: Final = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,  # 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

TokenType = Literal["access", "refresh"]


# ------------------------------------------------------------ palavras-passe
def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(stored_hash: str) -> bool:
    """Permite subir os parâmetros de custo sem forçar reposições de palavra-passe."""
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


def dummy_verify() -> None:
    """Consome tempo equivalente a uma verificação real.

    Chamado quando o utilizador não existe, para que o tempo de resposta do
    login não revele se um endereço está registado (enumeração de contas).
    """
    _hasher.hash("verificacao-artificial-para-tempo-constante")


# -------------------------------------------------------------------- tokens
def create_access_token(
    *,
    subject: uuid.UUID,
    role: str,
    permissions: list[str],
    session_id: uuid.UUID,
    expires_delta: timedelta | None = None,
) -> tuple[str, datetime]:
    """Devolve (token, instante de expiração).

    As permissões viajam dentro do token para o frontend saber o que
    apresentar, mas *não* são a fonte de verdade da autorização: cada pedido
    reconfirma o perfil actual contra a base de dados. Ver `app/core/deps.py`.
    """
    now = datetime.now(UTC)
    expire = now + (expires_delta or timedelta(minutes=settings.access_token_ttl_minutes))
    payload: dict[str, Any] = {
        "sub": str(subject),
        "sid": str(session_id),
        "role": role,
        "perms": permissions,
        "type": "access",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": secrets.token_urlsafe(16),
        "iss": settings.app_name,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, expire


def decode_access_token(token: str) -> dict[str, Any]:
    """Descodifica e valida um access token. Levanta `jwt.PyJWTError` se inválido."""
    payload = jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
        issuer=settings.app_name,
        options={"require": ["exp", "iat", "sub", "type"]},
    )
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("Tipo de token incorrecto.")
    return payload


def generate_refresh_token() -> tuple[str, str]:
    """Devolve (token em claro, hash a persistir).

    O token em claro só existe na resposta ao cliente; a base de dados guarda
    exclusivamente o hash.
    """
    raw = secrets.token_urlsafe(48)
    return raw, hash_refresh_token(raw)


def hash_refresh_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


# ------------------------------------------------------------------ diversos
def generate_api_key() -> tuple[str, str, str]:
    """Chave de API para fontes de ingestão (Wazuh, Suricata, ...).

    Devolve (chave em claro, prefixo, hash). O prefixo é guardado em claro para
    que a UI possa identificar a chave sem a revelar, e para que a procura no
    momento da autenticação seja indexada em vez de percorrer todas as chaves.
    """
    raw = secrets.token_urlsafe(32)
    prefix = raw[:8]
    return raw, prefix, hashlib.sha256(raw.encode("utf-8")).hexdigest()


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
