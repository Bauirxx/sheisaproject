/**
 * Portal externo (§37) — comunicar um incidente sem conta na plataforma.
 *
 * É o único ecrã que se abre sem sessão, e por isso é autónomo: não usa a
 * navegação interna, não mostra nada da plataforma e não pede credenciais. Quem
 * chega aqui é um constituinte, um cliente ou outra organização — a diferença de
 * natureza entre uma ferramenta de SOC interno e uma de CSIRT.
 *
 * Duas decisões que o §37 impõe e que se lêem no ecrã:
 *
 * **O código de acompanhamento aparece uma única vez.** A base de dados guarda
 * apenas o seu resumo, pelo que nem o administrador o pode recuperar. A página
 * diz isso antes de o mostrar, e o botão de copiar existe para reduzir a
 * probabilidade de alguém o perder por o transcrever à mão.
 *
 * **A consulta de estado não revela nada de dentro.** Não mostra o incidente, nem
 * quem avaliou, nem notas — apenas em que ponto está. O que se devolve é decidido
 * no servidor; esta página não filtra nada, porque um filtro na interface seria
 * uma promessa que a API não cumpre.
 *
 * A classificação que o comunicante escolhe é **opcional** de propósito. Quem
 * comunica um incidente muitas vezes não sabe classificá-lo, e obrigá-lo a
 * escolher produziria classificações inventadas, piores do que a ausência.
 */

import { useMutation } from "@tanstack/react-query";
import { useState } from "react";

import { pedir } from "@/api/cliente";
import type {
  ComunicacaoSubmetida,
  EstadoPublicoDaComunicacao,
} from "@/api/tipos";
import { Erro, instante, legivel } from "@/componentes/comuns";
import { CATEGORIAS, SEVERIDADES } from "@/componentes/listagem";

const APARENCIA_DO_ESTADO: Record<string, string> = {
  RECEBIDA: "distintivo--neutro",
  EM_TRIAGEM: "distintivo--aviso",
  ACEITE: "distintivo--sucesso",
  RECUSADA: "distintivo--neutro",
  DUPLICADA: "distintivo--neutro",
};

function Moldura({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="pilha"
      style={{
        maxWidth: "48rem",
        margin: "0 auto",
        padding: "var(--espaco-5) var(--espaco-4)",
        gap: "var(--espaco-4)",
      }}
    >
      <header className="pilha" style={{ gap: "var(--espaco-2)" }}>
        <h1 className="pagina__titulo">Comunicar um incidente de segurança</h1>
        <p className="pagina__descricao">
          Este formulário é para comunicar um incidente à equipa de resposta. Não
          é necessário ter conta. Receberá uma referência e um código com que pode
          consultar o estado da sua comunicação.
        </p>
      </header>
      {children}
    </div>
  );
}

// ------------------------------------------------------------ submissão
function Submeter({ aoConsultar }: { aoConsultar: () => void }) {
  const [nome, definirNome] = useState("");
  const [email, definirEmail] = useState("");
  const [organizacao, definirOrganizacao] = useState("");
  const [telefone, definirTelefone] = useState("");
  const [assunto, definirAssunto] = useState("");
  const [descricao, definirDescricao] = useState("");
  const [categoria, definirCategoria] = useState("");
  const [severidade, definirSeveridade] = useState("");
  const [indicadores, definirIndicadores] = useState("");
  const [copiado, definirCopiado] = useState(false);

  const submeter = useMutation({
    mutationFn: () =>
      pedir<ComunicacaoSubmetida>("/public/reports", {
        metodo: "POST",
        // `renovavel: false` porque este ecrã não tem sessão para renovar: sem
        // isto, um erro inesperado tentaria renovar e acabaria por accionar a
        // saída de sessão, num ecrã onde não há sessão nenhuma.
        renovavel: false,
        corpo: {
          reporter_name: nome,
          reporter_email: email,
          reporter_organisation: organizacao,
          reporter_phone: telefone,
          subject: assunto,
          description: descricao,
          claimed_category: categoria || null,
          claimed_severity: severidade || null,
          reported_indicators: indicadores,
        },
      }),
  });

  if (submeter.data) {
    const { referencia, codigo_de_acompanhamento, aviso } = submeter.data;
    return (
      <div className="cartao pilha" style={{ gap: "var(--espaco-3)" }}>
        <h2>Comunicação registada</h2>
        <p className="secundario">
          A sua comunicação ficou registada com a referência abaixo e está na fila
          para ser avaliada.
        </p>

        <div className="propriedades">
          <div className="propriedade">
            <span className="propriedade__rotulo">Referência</span>
            <span className="propriedade__valor mono">{referencia}</span>
          </div>
        </div>

        <div className="mensagem mensagem--aviso">{aviso}</div>

        <label className="campo">
          <span className="campo__etiqueta">Código de acompanhamento</span>
          <code className="bloco-bruto mono" style={{ wordBreak: "break-all" }}>
            {codigo_de_acompanhamento}
          </code>
        </label>

        <div className="linha" style={{ gap: "var(--espaco-2)", flexWrap: "wrap" }}>
          <button
            type="button"
            className="botao botao--primario botao--pequeno"
            onClick={() => {
              void navigator.clipboard
                ?.writeText(`${referencia} ${codigo_de_acompanhamento}`)
                .then(() => definirCopiado(true));
            }}
          >
            {copiado ? "Copiado" : "Copiar referência e código"}
          </button>
          <button
            type="button"
            className="botao botao--pequeno"
            onClick={aoConsultar}
          >
            Consultar o estado
          </button>
          <button
            type="button"
            className="botao botao--discreto botao--pequeno"
            onClick={() => submeter.reset()}
          >
            Comunicar outro incidente
          </button>
        </div>
      </div>
    );
  }

  const podeSubmeter =
    nome.trim().length >= 2 &&
    email.includes("@") &&
    assunto.trim().length >= 5 &&
    descricao.trim().length >= 20;

  return (
    <form
      className="cartao pilha"
      style={{ gap: "var(--espaco-3)" }}
      onSubmit={(e) => {
        e.preventDefault();
        submeter.mutate();
      }}
    >
      <h2>Os seus dados</h2>
      <p className="terciario">
        Servem para a equipa poder pedir esclarecimentos e para o informar do
        resultado. Não são publicados.
      </p>

      <div className="linha" style={{ gap: "var(--espaco-3)", flexWrap: "wrap" }}>
        <label className="campo" style={{ flex: "1 1 14rem" }}>
          <span className="campo__etiqueta">Nome *</span>
          <input
            type="text"
            required
            minLength={2}
            maxLength={160}
            value={nome}
            onChange={(e) => definirNome(e.target.value)}
          />
        </label>
        <label className="campo" style={{ flex: "1 1 14rem" }}>
          <span className="campo__etiqueta">Endereço de correio electrónico *</span>
          <input
            type="email"
            required
            maxLength={254}
            value={email}
            onChange={(e) => definirEmail(e.target.value)}
          />
        </label>
      </div>

      <div className="linha" style={{ gap: "var(--espaco-3)", flexWrap: "wrap" }}>
        <label className="campo" style={{ flex: "1 1 14rem" }}>
          <span className="campo__etiqueta">Organização</span>
          <input
            type="text"
            maxLength={160}
            value={organizacao}
            onChange={(e) => definirOrganizacao(e.target.value)}
          />
        </label>
        <label className="campo" style={{ flex: "1 1 14rem" }}>
          <span className="campo__etiqueta">Telefone</span>
          <input
            type="tel"
            maxLength={40}
            value={telefone}
            onChange={(e) => definirTelefone(e.target.value)}
          />
        </label>
      </div>

      <div className="separador" />

      <h2>O que aconteceu</h2>

      <label className="campo">
        <span className="campo__etiqueta">Assunto *</span>
        <input
          type="text"
          required
          minLength={5}
          maxLength={300}
          placeholder="Uma frase que resuma a situação"
          value={assunto}
          onChange={(e) => definirAssunto(e.target.value)}
        />
      </label>

      <label className="campo">
        <span className="campo__etiqueta">Descrição *</span>
        <textarea
          className="area-texto"
          required
          minLength={20}
          maxLength={20000}
          rows={7}
          placeholder="O que observou, quando, que sistemas ou pessoas foram afectados, e o que já fez."
          value={descricao}
          onChange={(e) => definirDescricao(e.target.value)}
        />
        <span className="campo__ajuda">
          {descricao.trim().length < 20
            ? `Pelo menos 20 caracteres (${descricao.trim().length} até agora).`
            : "Quanto mais concreto, mais rápido é avaliado."}
        </span>
      </label>

      <label className="campo">
        <span className="campo__etiqueta">
          Endereços, domínios ou ligações envolvidos
        </span>
        <textarea
          className="area-texto"
          maxLength={4000}
          rows={3}
          placeholder="Um por linha, se souber. Ex.: 203.0.113.10, site-falso.example"
          value={indicadores}
          onChange={(e) => definirIndicadores(e.target.value)}
        />
        <span className="campo__ajuda">
          Serão verificados por um analista antes de serem usados. Se não tiver
          esta informação, deixe em branco.
        </span>
      </label>

      <div className="separador" />

      <h2>Classificação (opcional)</h2>
      <p className="terciario">
        Se não souber, deixe sem escolher — a equipa classifica. O que indicar
        aqui fica registado como a sua avaliação, não como a da equipa.
      </p>

      <div className="linha" style={{ gap: "var(--espaco-3)", flexWrap: "wrap" }}>
        <label className="campo" style={{ flex: "1 1 14rem" }}>
          <span className="campo__etiqueta">Tipo de incidente</span>
          <select
            className="selector"
            value={categoria}
            onChange={(e) => definirCategoria(e.target.value)}
          >
            <option value="">— não sei —</option>
            {CATEGORIAS.map((c) => (
              <option key={c.valor} value={c.valor}>
                {c.rotulo}
              </option>
            ))}
          </select>
        </label>
        <label className="campo" style={{ flex: "1 1 14rem" }}>
          <span className="campo__etiqueta">Gravidade que atribui</span>
          <select
            className="selector"
            value={severidade}
            onChange={(e) => definirSeveridade(e.target.value)}
          >
            <option value="">— não sei —</option>
            {SEVERIDADES.map((s) => (
              <option key={s.valor} value={s.valor}>
                {s.rotulo}
              </option>
            ))}
          </select>
        </label>
      </div>

      {submeter.error ? <Erro erro={submeter.error} /> : null}

      <div className="linha" style={{ gap: "var(--espaco-2)", flexWrap: "wrap" }}>
        <button
          className="botao botao--primario"
          disabled={submeter.isPending || !podeSubmeter}
        >
          {submeter.isPending ? "A enviar…" : "Comunicar incidente"}
        </button>
        <button
          type="button"
          className="botao botao--discreto"
          onClick={aoConsultar}
        >
          Já comuniquei — consultar o estado
        </button>
      </div>
    </form>
  );
}

// --------------------------------------------------------- acompanhamento
function Consultar({ aoComunicar }: { aoComunicar: () => void }) {
  const [referencia, definirReferencia] = useState("");
  const [codigo, definirCodigo] = useState("");

  const consultar = useMutation({
    mutationFn: () =>
      pedir<EstadoPublicoDaComunicacao>(
        `/public/reports/${encodeURIComponent(referencia.trim())}?codigo=${encodeURIComponent(codigo.trim())}`,
        { renovavel: false },
      ),
  });

  return (
    <div className="pilha" style={{ gap: "var(--espaco-3)" }}>
      <form
        className="cartao pilha"
        style={{ gap: "var(--espaco-3)" }}
        onSubmit={(e) => {
          e.preventDefault();
          consultar.mutate();
        }}
      >
        <h2>Consultar o estado</h2>
        <p className="terciario">
          Precisa da referência e do código que recebeu ao comunicar. Se perdeu o
          código, não é possível recuperá-lo — comunique de novo, mencionando a
          referência anterior.
        </p>

        <label className="campo">
          <span className="campo__etiqueta">Referência</span>
          <input
            type="text"
            required
            placeholder="COM-00001"
            className="mono"
            value={referencia}
            onChange={(e) => definirReferencia(e.target.value)}
          />
        </label>

        <label className="campo">
          <span className="campo__etiqueta">Código de acompanhamento</span>
          <input
            type="text"
            required
            minLength={8}
            className="mono"
            value={codigo}
            onChange={(e) => definirCodigo(e.target.value)}
          />
        </label>

        {consultar.error ? (
          <div className="mensagem mensagem--aviso">
            Não foi encontrada nenhuma comunicação com esta referência e este
            código. Confirme os dois — são pedidos em conjunto de propósito.
          </div>
        ) : null}

        <div className="linha" style={{ gap: "var(--espaco-2)", flexWrap: "wrap" }}>
          <button
            className="botao botao--primario"
            disabled={
              consultar.isPending ||
              referencia.trim().length < 5 ||
              codigo.trim().length < 8
            }
          >
            {consultar.isPending ? "A consultar…" : "Consultar"}
          </button>
          <button type="button" className="botao botao--discreto" onClick={aoComunicar}>
            Comunicar um incidente
          </button>
        </div>
      </form>

      {consultar.data ? (
        <div className="cartao pilha" style={{ gap: "var(--espaco-3)" }}>
          <div className="linha linha--espalhada">
            <strong className="mono">{consultar.data.referencia}</strong>
            <span
              className={`distintivo ${
                APARENCIA_DO_ESTADO[consultar.data.estado] ?? "distintivo--neutro"
              }`}
            >
              {legivel(consultar.data.estado)}
            </span>
          </div>

          <p className="secundario">{consultar.data.situacao}</p>

          <div className="propriedades">
            <div className="propriedade">
              <span className="propriedade__rotulo">Comunicada</span>
              <span className="propriedade__valor">
                {instante(consultar.data.recebida_em)}
              </span>
            </div>
            <div className="propriedade">
              <span className="propriedade__rotulo">Avaliada</span>
              <span className="propriedade__valor">
                {consultar.data.avaliada_em
                  ? instante(consultar.data.avaliada_em)
                  : "ainda não"}
              </span>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export function Comunicar() {
  const [vista, definirVista] = useState<"submeter" | "consultar">("submeter");

  return (
    <Moldura>
      {vista === "submeter" ? (
        <Submeter aoConsultar={() => definirVista("consultar")} />
      ) : (
        <Consultar aoComunicar={() => definirVista("submeter")} />
      )}
    </Moldura>
  );
}
