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
import { Alertas } from "@/paginas/Alertas";
import { Aprovacoes } from "@/paginas/Aprovacoes";
import { Entrada } from "@/paginas/Entrada";
import { IncidenteDetalhe } from "@/paginas/IncidenteDetalhe";
import { IncidenteNovo } from "@/paginas/IncidenteNovo";
import { Incidentes } from "@/paginas/Incidentes";
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
      <Route
        element={
          <ExigirSessao>
            <Disposicao />
          </ExigirSessao>
        }
      >
        <Route path="/painel" element={<Painel />} />
        <Route path="/alertas" element={<Alertas />} />
        <Route path="/incidentes" element={<Incidentes />} />
        <Route path="/incidentes/novo" element={<IncidenteNovo />} />
        <Route path="/incidentes/:id" element={<IncidenteDetalhe />} />
        <Route path="/recomendacoes" element={<Recomendacoes />} />
        <Route path="/aprovacoes" element={<Aprovacoes />} />
        <Route path="/relatorios" element={<Relatorios />} />
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
