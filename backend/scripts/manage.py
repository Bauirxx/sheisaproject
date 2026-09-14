"""Utilitário de linha de comandos da plataforma.

Uso:
    python -m scripts.manage init [--admin-email ...] [--admin-password ...]
    python -m scripts.manage mitre-load [--file caminho.json]
    python -m scripts.manage seed-correlation
    python -m scripts.manage seed-playbooks
    python -m scripts.manage create-api-key --name "Wazuh" --kind WAZUH
    python -m scripts.manage demo [--reset]
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

# Permite correr o módulo a partir da raiz de `backend/`.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.database import dispose_engine, get_sessionmaker  # noqa: E402


def _banner(text: str) -> None:
    print(f"\n\033[1m{text}\033[0m")
    print("-" * len(text))


async def cmd_init(args: argparse.Namespace) -> int:
    from app.services import bootstrap

    factory = get_sessionmaker()
    async with factory() as session:
        _banner("Inicialização da plataforma SHEISA")

        created, updated = await bootstrap.sync_permissions(session)
        print(f"  Permissões: {created} criada(s), {updated} actualizada(s).")

        roles_created, roles_kept = await bootstrap.sync_roles(session)
        print(f"  Perfis: {roles_created} criado(s), {roles_kept} já existente(s).")

        team = await bootstrap.ensure_default_team(session)
        print(f"  Equipa por omissão: {team.name}")

        email = args.admin_email or os.environ.get("SHEISA_ADMIN_EMAIL", "admin@sheisa.local")
        password = args.admin_password or os.environ.get("SHEISA_ADMIN_PASSWORD")
        user, generated = await bootstrap.ensure_admin(
            session, email=email, password=password
        )

        await session.commit()

        if generated:
            print("\n  \033[1mConta de administração criada.\033[0m")
            print(f"    Utilizador:   {user.email}")
            print(f"    Palavra-passe: {generated}")
            print(
                "\n  Esta palavra-passe não volta a ser apresentada e tem de ser\n"
                "  alterada no primeiro início de sessão."
            )
        else:
            print(f"  Conta de administração: {user.email} (já existia)")

    print("\nInicialização concluída.\n")
    return 0


async def cmd_mitre_load(args: argparse.Namespace) -> int:
    from app.services.mitre_service import load_attack_data

    factory = get_sessionmaker()
    async with factory() as session:
        _banner("Carregamento do catálogo MITRE ATT&CK")
        stats = await load_attack_data(
            session,
            source_file=Path(args.file) if args.file else None,
            force_download=args.download,
        )
        await session.commit()
        print(f"  Versão ATT&CK:  {stats['version']}")
        print(f"  Tácticas:       {stats['tactics']}")
        print(f"  Técnicas:       {stats['techniques']}")
        print(f"  Subtécnicas:    {stats['subtechniques']}")
    print()
    return 0


async def cmd_seed_assets(args: argparse.Namespace) -> int:
    from app.services.seed_service import seed_lab_assets

    factory = get_sessionmaker()
    async with factory() as session:
        _banner("Inventario de activos do laboratorio")
        created, existing = await seed_lab_assets(session)
        await session.commit()
        print(f"  {created} criado(s), {existing} ja existente(s).")
    print()
    return 0


async def cmd_seed_integrations(args: argparse.Namespace) -> int:
    from app.services.integration_service import ensure_catalog

    factory = get_sessionmaker()
    async with factory() as session:
        _banner("Catalogo de integracoes")
        created = await ensure_catalog(session)
        await session.commit()
        print(f"  {created} integracao(oes) registada(s).")
    print()
    return 0


async def cmd_seed_correlation(args: argparse.Namespace) -> int:
    from app.services.seed_service import seed_correlation_rules

    factory = get_sessionmaker()
    async with factory() as session:
        _banner("Regras de correlação")
        created, existing = await seed_correlation_rules(session)
        await session.commit()
        print(f"  {created} criada(s), {existing} já existente(s).")
    print()
    return 0


async def cmd_seed_playbooks(args: argparse.Namespace) -> int:
    from app.services.seed_service import seed_playbooks

    factory = get_sessionmaker()
    async with factory() as session:
        _banner("Playbooks de resposta")
        created, existing = await seed_playbooks(session)
        await session.commit()
        print(f"  {created} criado(s), {existing} já existente(s).")
    print()
    return 0


async def cmd_create_api_key(args: argparse.Namespace) -> int:
    from app.services.integration_service import create_ingestion_key

    factory = get_sessionmaker()
    async with factory() as session:
        _banner("Nova chave de ingestão")
        raw, api_key = await create_ingestion_key(
            session, name=args.name, kind=args.kind, description=args.description or ""
        )
        await session.commit()
        print(f"  Nome:    {api_key.name}")
        print(f"  Prefixo: {api_key.key_prefix}")
        print(f"\n  \033[1mChave: {raw}\033[0m")
        print("\n  Guarde-a agora: apenas o hash é persistido e a chave não")
        print("  poderá voltar a ser apresentada.")
    print()
    return 0


async def cmd_demo(args: argparse.Namespace) -> int:
    from app.services.demo_service import run_demo_scenario

    factory = get_sessionmaker()
    async with factory() as session:
        _banner("Cenário de demonstração")
        summary = await run_demo_scenario(session, reset=args.reset)
        await session.commit()
        for line in summary:
            print(f"  {line}")
    print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="manage", description="Utilitário de administração da plataforma SHEISA."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Cria permissões, perfis e conta de administração.")
    p_init.add_argument("--admin-email", dest="admin_email")
    p_init.add_argument("--admin-password", dest="admin_password")
    p_init.set_defaults(func=cmd_init)

    p_mitre = sub.add_parser("mitre-load", help="Carrega o catálogo MITRE ATT&CK.")
    p_mitre.add_argument("--file", help="Ficheiro STIX local (opcional).")
    p_mitre.add_argument(
        "--download", action="store_true", help="Força nova transferência."
    )
    p_mitre.set_defaults(func=cmd_mitre_load)

    p_corr = sub.add_parser("seed-correlation", help="Instala regras de correlação base.")
    p_corr.set_defaults(func=cmd_seed_correlation)

    p_assets = sub.add_parser("seed-assets", help="Instala o inventário do laboratório.")
    p_assets.set_defaults(func=cmd_seed_assets)

    p_integ = sub.add_parser("seed-integrations", help="Regista o catálogo de integrações.")
    p_integ.set_defaults(func=cmd_seed_integrations)

    p_play = sub.add_parser("seed-playbooks", help="Instala playbooks de resposta base.")
    p_play.set_defaults(func=cmd_seed_playbooks)

    p_key = sub.add_parser("create-api-key", help="Cria uma chave de ingestão.")
    p_key.add_argument("--name", required=True)
    p_key.add_argument("--kind", required=True, help="WAZUH | SURICATA | QRADAR | ...")
    p_key.add_argument("--description")
    p_key.set_defaults(func=cmd_create_api_key)

    p_demo = sub.add_parser("demo", help="Executa o cenário de demonstração.")
    p_demo.add_argument(
        "--reset", action="store_true", help="Remove dados de demonstração anteriores."
    )
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main() -> int:
    args = build_parser().parse_args()

    async def _run() -> int:
        try:
            return await args.func(args)
        finally:
            await dispose_engine()

    try:
        return asyncio.run(_run())
    except KeyboardInterrupt:
        print("\nInterrompido.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
