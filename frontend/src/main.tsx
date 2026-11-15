import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import App from "./App.jsx";
import { RealtimeProvider } from "./lib/realtime.jsx";
import { I18nProvider } from "./i18n/I18n.jsx";
import { queryClient } from "./lib/serverState.js";
import "./styles/global.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <I18nProvider>
      <QueryClientProvider client={queryClient}>
        <RealtimeProvider>
          <App />
        </RealtimeProvider>
      </QueryClientProvider>
    </I18nProvider>
  </React.StrictMode>,
);
