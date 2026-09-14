"""Configuração da aplicação.

Todos os segredos são lidos de variáveis de ambiente (§23). Nada de credenciais
no código. A aplicação recusa-se a arrancar em produção sem um segredo JWT
adequado — falhar no arranque é preferível a servir tráfego com um segredo fraco.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path
from typing import Literal

from typing import Annotated

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Raiz do repositório: .../sheisa_project
PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(PROJECT_ROOT / ".env", PROJECT_ROOT / "backend" / ".env"),
        env_prefix="SHEISA_",
        extra="ignore",
        case_sensitive=False,
    )

    # ---------------------------------------------------------------- geral
    app_name: str = "SHEISA"
    app_title: str = "SHEISA — Plataforma de Gestão e Resposta a Incidentes"
    environment: Literal["development", "test", "production"] = "development"
    api_prefix: str = "/api"

    # ------------------------------------------------------------ base dados
    database_url: str = "postgresql+asyncpg://sheisa:sheisa@127.0.0.1:15433/sheisa"
    test_database_url: str = (
        "postgresql+asyncpg://sheisa:sheisa_test@127.0.0.1:15434/sheisa_test"
    )
    db_echo: bool = False
    db_pool_size: int = 10
    db_max_overflow: int = 20

    # --------------------------------------------------------------- sessões
    jwt_secret: str = Field(default="")
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 30
    refresh_token_ttl_days: int = 7
    # Bloqueio de conta após tentativas falhadas consecutivas (§23).
    max_failed_logins: int = 5
    lockout_minutes: int = 15

    # ------------------------------------------------------------- segurança
    # `NoDecode` impede o pydantic-settings de tentar interpretar o valor como
    # JSON antes dos validadores correrem, permitindo a forma "a,b,c" no .env.
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173"]
    )
    # Limitação de pedidos: janela deslizante por (identidade, rota).
    rate_limit_enabled: bool = True
    rate_limit_default_per_minute: int = 300
    rate_limit_auth_per_minute: int = 10
    rate_limit_ingest_per_minute: int = 1200

    # ------------------------------------------------------------ evidências
    evidence_storage_path: Path = PROJECT_ROOT / "backend" / "var" / "evidence"
    evidence_max_bytes: int = 64 * 1024 * 1024  # 64 MiB
    # Extensões aceites para carregamento. Executáveis são aceites como
    # artefactos de análise mas nunca servidos com um content-type executável.
    evidence_allowed_suffixes: Annotated[set[str], NoDecode] = Field(
        default_factory=lambda: {
            ".log", ".txt", ".json", ".xml", ".csv", ".yaml", ".yml",
            ".pcap", ".pcapng", ".evtx", ".eml", ".msg",
            ".png", ".jpg", ".jpeg", ".gif", ".webp",
            ".pdf", ".zip", ".gz", ".tar", ".7z",
            ".bin", ".dmp", ".exe", ".dll", ".sh", ".ps1",
        }
    )

    # ----------------------------------------------------------------- MITRE
    mitre_stix_url: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "master/enterprise-attack/enterprise-attack.json"
    )
    mitre_stix_cache: Path = PROJECT_ROOT / "backend" / "var" / "mitre" / "enterprise-attack.json"

    # --------------------------------------------------------------- motores
    # Janela em que dois alertas podem ser considerados parte da mesma
    # actividade pelo motor de correlação.
    correlation_window_minutes: int = 60
    # Pontuação mínima (0-100) para um alerta ser promovido automaticamente.
    auto_promote_min_score: int = 75

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, v: object) -> object:
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @field_validator("evidence_allowed_suffixes", mode="before")
    @classmethod
    def _split_suffixes(cls, v: object) -> object:
        if isinstance(v, str):
            return {s.strip().lower() for s in v.split(",") if s.strip()}
        return v

    @model_validator(mode="after")
    def _validate_secrets(self) -> "Settings":
        if not self.jwt_secret:
            if self.environment == "production":
                raise RuntimeError(
                    "SHEISA_JWT_SECRET é obrigatório em produção. "
                    "Gere com: python -c \"import secrets;print(secrets.token_urlsafe(48))\""
                )
            # Em desenvolvimento/teste geramos um segredo efémero. Isto invalida
            # as sessões a cada reinício, o que é o comportamento correcto: evita
            # que um segredo previsível se instale por descuido.
            object.__setattr__(self, "jwt_secret", secrets.token_urlsafe(48))
        elif len(self.jwt_secret) < 32 and self.environment == "production":
            raise RuntimeError("SHEISA_JWT_SECRET demasiado curto (mínimo 32 caracteres).")
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def effective_database_url(self) -> str:
        return self.test_database_url if self.environment == "test" else self.database_url


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
