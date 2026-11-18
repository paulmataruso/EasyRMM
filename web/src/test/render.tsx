import type { ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router";
import { AuthProvider } from "../auth/AuthContext";
import { ToastProvider } from "../components/Toast";
import { App } from "../App";

/** Shows the router location so tests can assert redirects. */
function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{`${location.pathname}${location.search}`}</output>;
}

export function testQueryClient(): QueryClient {
  return new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } } });
}

/** Renders children inside the same providers as main.tsx, at the given URL. */
export function renderWithProviders(children: ReactNode, path = "/") {
  const client = testQueryClient();
  return {
    client,
    ...render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={[path]}>
          <ToastProvider>
            <AuthProvider>
              {children}
              <LocationProbe />
            </AuthProvider>
          </ToastProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    ),
  };
}

/** Renders the whole console at the given URL. */
export function renderApp(path = "/") {
  return renderWithProviders(<App />, path);
}
