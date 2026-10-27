/* Render helpers: a page inside the same providers App.tsx uses. */
import React, { Suspense } from "react";
import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { RealtimeProvider } from "../lib/realtime.js";
import { I18nProvider } from "../i18n/I18n.jsx";

export function renderWithProviders(ui: React.ReactElement, { route = "/" }: { route?: string } = {}) {
  return render(
    <I18nProvider>
      <RealtimeProvider>
        <MemoryRouter initialEntries={[route]}>
          <Suspense fallback={<div data-testid="suspense">loading</div>}>{ui}</Suspense>
        </MemoryRouter>
      </RealtimeProvider>
    </I18nProvider>,
  );
}
