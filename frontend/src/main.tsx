import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";
import { RealtimeProvider } from "./lib/realtime.jsx";
import { I18nProvider } from "./i18n/I18n.jsx";
import "./styles/global.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <I18nProvider>
      <RealtimeProvider>
        <App />
      </RealtimeProvider>
    </I18nProvider>
  </React.StrictMode>,
);
