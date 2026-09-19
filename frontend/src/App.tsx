/**
 * Composicao da aplicacao: cliente de dados, sessao e encaminhamento.
 *
 * `ErroDaApi` com 401 ou 403 nao e repetido: renovar a sessao ja foi tentado
 * pelo cliente HTTP, e insistir num 403 so multiplica entradas NEGADO na
 * auditoria sem qualquer hipotese de sucesso.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

import { ErroDaApi } from "@/api/cliente";
import { ProvedorDeSessao, useSessao } from "@/autenticacao/contexto";
import { Carregando } from "@/componentes/comuns";
import { Disposicao } from "@/componentes/Disposicao";
import { Administracao, PaginaDePlaybooks } from "@/paginas/Administracao";
import { Alertas } from "@/paginas/Alertas";
import { Auditoria } from "@/paginas/Auditoria";
import { CentroDeOperacoes } from "@/paginas/CentroDeOperacoes";
import { Activos, Indicadores, Mitre } from "@/paginas/Catalogo";
import { Aprovacoes } from "@/paginas/Aprovacoes";
import { Comunicacoes } from "@/paginas/Comunicacoes";
import { Comunicar } from "@/paginas/Comunicar";
import { Entrada } from "@/paginas/Entrada";
import { Eventos } from "@/paginas/Eventos";
import { IncidenteDetalhe } from "@/paginas/IncidenteDetalhe";
import { IncidenteNovo } from "@/paginas/IncidenteNovo";
import { Incidentes } from "@/paginas/Incidentes";
import { Integracoes, Notificacoes } from "@/paginas/Integracoes";
import { Painel } from "@/paginas/Painel";
import { Recomendacoes } from "@/paginas/Recomendacoes";
import { Relatorios } from "@/paginas/Relatorios";

const clienteDeDados = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      refetchOnWindowFocus: false,
      retry: (tentativas, erro) => {
        if (erro instanceof ErroDaApi && (erro.semSessao || erro.semPermissao)) {
          return false;
        }
        return tentativas < 2;
      },
    },
    mutations: { retry: false },
  },
});

function ExigirSessao({ children }: { children: React.ReactNode }) {
  const { utilizador, aRecuperar } = useSessao();
  if (aRecuperar) return <Carregando texto="A verificar a sessao..." />;
  if (!utilizador) return <Navigate to="/entrar" replace />;
  return <>{children}</>;
}

function Encaminhamento() {
  return (
    <Routes>
      <Route path="/entrar" element={<Entrada />} />
      {/* Portal externo (§37): fora do `ExigirSessao` de propósito. Quem
          comunica um incidente não tem conta nem deve precisar de uma, e é a
          única parte da aplicação nessas condições. */}
      <Route path="/comunicar" element={<Comunicar />} />
      <Route
        element={
          <ExigirSessao>
            <Disposicao />
          </ExigirSessao>
        }
      >
        <Route path="/painel" element={<Painel />} />
        <Route path="/centro" element={<CentroDeOperacoes />} />
        <Route path="/alertas" element={<Alertas />} />
        <Route path="/comunicacoes" element={<Comunicacoes />} />
        <Route path="/eventos" element={<Eventos />} />
        <Route path="/incidentes" element={<Incidentes />} />
        <Route path="/incidentes/novo" element={<IncidenteNovo />} />
        <Route path="/incidentes/:id" element={<IncidenteDetalhe />} />
        <Route path="/recomendacoes" element={<Recomendacoes />} />
        <Route path="/aprovacoes" element={<Aprovacoes />} />
        <Route path="/relatorios" element={<Relatorios />} />
        <Route path="/indicadores" element={<Indicadores />} />
        <Route path="/activos" element={<Activos />} />
        <Route path="/mitre" element={<Mitre />} />
        <Route path="/auditoria" element={<Auditoria />} />
        <Route path="/integracoes" element={<Integracoes />} />
        <Route path="/notificacoes" element={<Notificacoes />} />
        <Route path="/administracao" element={<Administracao />} />
        <Route path="/playbooks" element={<PaginaDePlaybooks />} />
      </Route>
      <Route path="*" element={<Navigate to="/painel" replace />} />
    </Routes>
  );
}

export function App() {
  return (
    <QueryClientProvider client={clienteDeDados}>
      <ProvedorDeSessao>
        <BrowserRouter>
          <Encaminhamento />
        </BrowserRouter>
      </ProvedorDeSessao>
    </QueryClientProvider>
  );
}
