import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";
import { RealtimeProvider } from "./lib/realtime.jsx";
import "./styles/global.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RealtimeProvider>
      <App />
    </RealtimeProvider>
  </React.StrictMode>
);
