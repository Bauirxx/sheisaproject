"""Verifica que os campos que o frontend le existem mesmo nas respostas da API.

    python -m scripts.verificar_contrato <palavra-passe-de-administracao>

com a API a correr (`./scripts/api.sh start`).

**Porque existe.** O TypeScript garante coerencia interna, nao correspondencia
com o servidor: os tipos em `frontend/src/api/tipos.ts` foram escritos a mao a
partir das respostas reais. Um campo que na verdade se chama de outra maneira
compila sem erro e aparece na interface como "undefined".

Na primeira execucao apanhou tres divergencias reais: o incidente devolve
`team_id` e nao um objecto `team`; a listagem de alertas usa um esquema
reduzido, sem a decomposicao da triagem, que so vem no detalhe; e a evidencia
chama-se `original_filename`/`content_type`. Correr isto depois de mexer nos
esquemas do backend custa segundos e evita descobri-lo numa demonstracao.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8099/api"
PW = sys.argv[1]
falhas: list[str] = []


def pedir(caminho, token=None, metodo="GET", corpo=None):
    dados = json.dumps(corpo).encode() if corpo is not None else None
    req = urllib.request.Request(BASE + caminho, data=dados, method=metodo)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def conferir(nome, objecto, campos, caminho=""):
    """Confirma que todos os campos existem no objecto."""
    if objecto is None:
        falhas.append(f"{nome}: objecto ausente")
        return
    em_falta = [c for c in campos if c not in objecto]
    if em_falta:
        falhas.append(f"{nome}{caminho}: campos em falta -> {em_falta}")
    else:
        print(f"  ok  {nome} ({len(campos)} campos)")


estado, corpo = pedir("/auth/login", metodo="POST",
                      corpo={"email": "admin@sheisa.local", "password": PW})
assert estado == 200, corpo
token = corpo["access_token"]

print("== sessao ==")
conferir("RespostaEntrada", corpo,
         ["access_token", "refresh_token", "token_type", "expires_at", "user"])
conferir("Utilizador", corpo["user"],
         ["id", "email", "full_name", "is_active", "must_change_password",
          "role", "team", "last_login_at", "permissions"])

print("\n== painel ==")
_, painel = pedir("/dashboard", token)
conferir("Painel", painel,
         ["periodo_dias", "incidentes", "alertas", "eventos", "resposta", "inteligencia"])
conferir("Painel.incidentes", painel["incidentes"],
         ["total", "activos", "criticos", "em_investigacao", "resolvidos",
          "encerrados", "falsos_positivos", "fora_de_prazo", "sem_responsavel"])
conferir("Painel.alertas", painel["alertas"],
         ["total", "por_triar", "no_periodo", "descartados_ou_falsos_positivos",
          "taxa_falsos_positivos_percentagem"])
conferir("Painel.resposta", painel["resposta"],
         ["aprovacoes_pendentes", "accoes_executadas", "tarefas_pendentes"])

print("\n== listagens (envelope) ==")
_, lista = pedir("/incidents?size=50", token)
conferir("Pagina", lista, ["itens", "total", "pagina", "tamanho", "total_paginas"])

demo = [i for i in lista["itens"] if i.get("is_demo_data")]
alvo = demo[0] if demo else lista["itens"][0]

print("\n== incidente (resumo na lista) ==")
conferir("IncidenteResumo", alvo,
         ["id", "reference", "title", "category", "severity", "priority",
          "status", "assignee", "detected_at", "due_at", "is_demo_data"])

print("\n== incidente (detalhe) ==")
_, det = pedir(f"/incidents/{alvo['id']}", token)
conferir("Incidente", det,
         ["description", "subtype", "confidence", "origin", "source_kind",
          "source_detail", "team_id", "acknowledged_at", "contained_at",
          "eradicated_at", "resolved_at", "closed_at", "resolution_summary",
          "lessons_learned", "false_positive_reason", "tags",
          "transicoes_permitidas", "metricas"])
conferir("MetricasDoIncidente", det["metricas"],
         ["tempo_ate_reconhecimento_segundos", "tempo_ate_contencao_segundos",
          "tempo_ate_resolucao_segundos", "dentro_do_prazo", "alertas_associados",
          "observacoes", "evidencias", "tarefas_totais", "tarefas_concluidas",
          "accoes_executadas"])

if det.get("assignee"):
    conferir("ResumoUtilizador (assignee)", det["assignee"], ["id", "nome", "email"])
else:
    print("  --  assignee nulo neste incidente; campo nao verificado")

if det.get("tecnicas"):
    conferir("TecnicaDoIncidente", det["tecnicas"][0],
             ["id", "technique", "is_asserted", "confidence", "rationale", "evidence_refs"])
    conferir("TecnicaDoIncidente.technique", det["tecnicas"][0]["technique"],
             ["technique_id", "name", "url", "is_subtechnique", "tactic_shortnames"])
else:
    print("  --  sem tecnicas neste incidente")

print("\n== alertas ==")
_, alertas = pedir(f"/alerts?incidente_id={alvo['id']}&size=50", token)
if alertas["total"]:
    a = alertas["itens"][0]
    # A listagem devolve o esquema reduzido...
    conferir("AlertaResumo", a,
             ["id", "reference", "title", "source_kind", "source_name", "severity",
              "status", "triage_score", "false_positive_score", "event_count",
              "first_event_at", "last_event_at", "rule_id", "rule_name",
              "incident_id", "correlation_outcome", "asset", "is_demo_data",
              "tags", "created_at"])
    # ...e a decomposicao so existe no detalhe, que e de onde o painel a pede.
    _, det_a = pedir(f"/alerts/{a['id']}", token)
    conferir("Alerta (detalhe)", det_a,
             ["description", "dedup_key", "triage_factors", "triage_rationale",
              "scored_at", "correlation_rationale", "correlated_at",
              "incident_reference", "transicoes_permitidas"])
    if det_a.get("triage_factors"):
        conferir("FactoresDeTriagem", det_a["triage_factors"],
                 ["motor", "versao", "total_bruto", "total_final", "factores"])
        nome, f = next(iter(det_a["triage_factors"]["factores"].items()))
        conferir(f"Factor[{nome}]", f, ["pontos", "razao"])
else:
    falhas.append("alertas: o filtro incidente_id nao devolveu nada")

print("\n== sub-recursos do incidente ==")
for caminho, nome, campos in [
    (f"/incidents/{alvo['id']}/comments", "Comentario",
     ["id", "body", "author", "is_internal", "is_system", "created_at"]),
    (f"/incidents/{alvo['id']}/observations", "Observacao",
     ["id", "ioc", "role", "context", "observed_at"]),
    (f"/evidence?incident_id={alvo['id']}", "Evidencia",
     ["id", "name", "description", "evidence_type", "original_filename",
      "content_type", "size_bytes", "sha256", "integrity_verified_at",
      "integrity_ok", "source", "collected_at", "uploaded_by", "created_at"]),
    (f"/incidents/{alvo['id']}/timeline", "EntradaDaLinhaTemporal",
     ["instante", "tipo", "titulo", "detalhe", "autor", "referencia", "recurso_id", "dados"]),
]:
    estado, corpo = pedir(caminho, token)
    if estado != 200:
        falhas.append(f"{nome}: HTTP {estado} em {caminho}")
        continue
    itens = corpo if isinstance(corpo, list) else corpo.get("itens", [])
    if itens:
        conferir(nome, itens[0], campos)
    else:
        print(f"  --  {nome}: sem registos para verificar")

print("\n== observacao.ioc ==")
estado, obs = pedir(f"/incidents/{alvo['id']}/observations", token)
if obs:
    conferir("Observacao.ioc", obs[0]["ioc"], ["id", "ioc_type", "value", "reputation"])

print("\n== accoes ==")
estado, accoes = pedir("/actions?size=10", token)
if accoes.get("total"):
    conferir("Accao", accoes["itens"][0],
             ["id", "reference", "incident_id", "action_kind", "title", "rationale",
              "target", "status", "risk_level", "proposed_by", "approvals",
              "executavel", "motivo_nao_executavel", "created_at"])
else:
    print("  --  sem accoes para verificar")

print("\n== recomendacoes ==")
estado, recs = pedir("/recommendations?size=10", token)
if recs.get("total"):
    conferir("Recomendacao", recs["itens"][0],
             ["id", "kind", "status", "target_type", "target_id", "title", "summary",
              "explanation", "confidence", "factors", "evidence_refs",
              "proposed_change", "engine", "engine_version", "decided_at",
              "decided_by", "decision_note", "applied", "created_at"])
    conferir("Recomendacao.factors", recs["itens"][0]["factors"],
             ["motor", "versao", "total", "factores"])
else:
    print("  --  sem recomendacoes pendentes para verificar")

print("\n== relatorios ==")
# Gera um relatorio para haver o que verificar, e confere o esquema do detalhe.
estado, novo_rel = pedir(
    "/reports/incident", token, metodo="POST", corpo={"incident_id": alvo["id"]}
)
if estado == 201:
    conferir("RelatorioDetalhado", novo_rel,
             ["id", "reference", "kind", "title", "parameters", "period_start",
              "period_end", "incident_id", "record_count", "created_at", "content"])
    _, lista_rel = pedir("/reports?size=5", token)
    if lista_rel.get("total"):
        conferir("Relatorio", lista_rel["itens"][0],
                 ["id", "reference", "title", "kind", "parameters", "period_start",
                  "period_end", "incident_id", "record_count", "created_at"])
else:
    falhas.append(f"relatorios: HTTP {estado} ao gerar")

print("\n== aprovacoes ==")
estado, aprov = pedir("/approvals?size=5", token)
if estado != 200:
    falhas.append(f"aprovacoes: HTTP {estado}")
else:
    conferir("Pagina (aprovacoes)", aprov,
             ["itens", "total", "pagina", "tamanho", "total_paginas"])
    if aprov["total"]:
        primeira = aprov["itens"][0]
        conferir("Accao (fila de aprovacao)", primeira,
                 ["id", "reference", "incident_id", "action_kind", "title",
                  "rationale", "target", "status", "risk_level", "proposed_by",
                  "approvals", "executavel", "motivo_nao_executavel", "created_at"])
        if primeira["approvals"]:
            conferir("Aprovacao", primeira["approvals"][0],
                     ["id", "decision", "required_permission", "requested_at",
                      "decided_at", "decided_by", "justification", "expires_at"])
    else:
        print("  --  fila de aprovacao vazia")

print("\n== grafo ==")
estado, grafo = pedir(f"/graph/incident/{alvo['id']}", token)
conferir("Grafo", grafo, ["nos", "arestas"])
if grafo.get("nos"):
    conferir("NoDoGrafo", grafo["nos"][0], ["id", "tipo", "rotulo"])
if grafo.get("arestas"):
    conferir("ArestaDoGrafo", grafo["arestas"][0], ["origem", "destino"])

print("\n== catalogo e administracao ==")
for caminho, nome, campos in [
    ("/iocs?size=2", "Indicador",
     ["id", "ioc_type", "value", "reputation", "confidence", "risk_score",
      "sighting_count", "first_seen", "last_seen", "source", "is_allowlisted",
      "allowlist_reason", "tags"]),
    ("/assets?size=2", "Activo",
     ["id", "identifier", "name", "asset_type", "criticality", "hostname",
      "ip_address", "owner", "is_active"]),
    ("/mitre/techniques?size=2", "Tecnica",
     ["id", "technique_id", "name", "description", "url", "is_subtechnique",
      "parent_technique_id", "tactic_shortnames", "platforms", "attack_version"]),
    ("/audit?size=2", "RegistoDeAuditoria",
     ["id", "created_at", "actor_email", "actor_role", "is_system_actor",
      "action", "resource_type", "resource_id", "resource_reference",
      "description", "old_value", "new_value", "changed_fields", "origin",
      "ip_address", "outcome", "failure_reason", "request_id"]),
    ("/users?size=2", "UtilizadorResumo",
     ["id", "email", "full_name", "is_active", "must_change_password", "role",
      "team", "last_login_at", "created_at"]),
    ("/roles", "PerfilDetalhado",
     ["id", "name", "description", "permissions"]),
    ("/playbooks", "Playbook",
     ["id", "name", "description", "is_enabled", "version", "auto_execute",
      "trigger_category", "trigger_min_severity", "execution_count",
      "success_count", "last_executed_at", "steps"]),
]:
    estado, corpo = pedir(caminho, token)
    if estado != 200:
        falhas.append(f"{nome}: HTTP {estado} em {caminho}")
        continue
    itens = corpo if isinstance(corpo, list) else corpo.get("itens", [])
    if itens:
        conferir(nome, itens[0], campos)
    else:
        print(f"  --  {nome}: sem registos para verificar")

estado, accoes_auditadas = pedir("/audit/actions", token)
if estado == 200 and isinstance(accoes_auditadas, list):
    print(f"  ok  /audit/actions ({len(accoes_auditadas)} accoes distintas)")
else:
    falhas.append(f"/audit/actions: HTTP {estado}")

print()
if falhas:
    print("DIVERGENCIAS ENTRE OS TIPOS E A API:")
    for f in falhas:
        print("  x", f)
    sys.exit(1)
print("Contrato confirmado: todos os campos que o frontend le existem na API.")
