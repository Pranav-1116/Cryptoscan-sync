import React, { useState, useEffect } from "react";
import { Modal, Badge } from "./ui";
import { apiSystemHealthStatus, SystemServiceHealth } from "../lib/api";

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export default function SystemHealthModal({ isOpen, onClose }: Props) {
  const [services, setServices] = useState<SystemServiceHealth[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (isOpen) {
      setLoading(true);
      apiSystemHealthStatus()
        .then((res) => {
          setServices(res);
          setLoading(false);
        })
        .catch(() => {
          setLoading(false);
        });
    }
  }, [isOpen]);

  const allOperational = services.every((s) => s.status === "Operational");

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="ZELNX System Status & 24/7 Engine Health">
      <div style={{ marginBottom: "16px" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "12px 16px",
            background: allOperational ? "rgba(34,197,94,0.08)" : "rgba(245,158,11,0.08)",
            border: `1px solid ${allOperational ? "rgba(34,197,94,0.3)" : "rgba(245,158,11,0.3)"}`,
            borderRadius: "8px",
            marginBottom: "16px",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span
              style={{
                width: 10,
                height: 10,
                borderRadius: "50%",
                background: allOperational ? "var(--green)" : "var(--amber)",
                boxShadow: `0 0 10px ${allOperational ? "var(--green)" : "var(--amber)"}`,
              }}
            />
            <span style={{ fontWeight: 600, fontSize: "14px", color: "var(--text)" }}>
              {allOperational ? "All Systems Fully Operational" : "Degraded Services Detected"}
            </span>
          </div>
          <Badge tone={allOperational ? "green" : "amber"}>
            {allOperational ? "100% HEALTHY" : "ATTENTION"}
          </Badge>
        </div>

        <p style={{ fontSize: "12.5px", color: "var(--dim)", margin: "0 0 16px", lineHeight: 1.5 }}>
          ZELNX continuous observation engines run 24/7 out-of-band across network, cloud, container, and hardware boundaries.
        </p>

        {loading ? (
          <div style={{ padding: "30px", textAlign: "center", color: "var(--dim)", fontFamily: "var(--mono)", fontSize: "13px" }}>
            Querying engine heartbeats...
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: "380px", overflowY: "auto", paddingRight: "4px" }}>
            {services.map((svc) => (
              <div
                key={svc.name}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "10px 14px",
                  background: "var(--bg-2)",
                  border: "1px solid var(--line)",
                  borderRadius: "6px",
                  fontSize: "13px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <span
                    style={{
                      width: 7,
                      height: 7,
                      borderRadius: "50%",
                      background: svc.status === "Operational" ? "var(--green)" : "var(--amber)",
                    }}
                  />
                  <span style={{ fontWeight: 500, color: "var(--text)" }}>{svc.name}</span>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
                  <span style={{ fontFamily: "var(--mono)", fontSize: "11px", color: "var(--dim)" }}>
                    {svc.latencyMs}ms
                  </span>
                  <Badge tone={svc.status === "Operational" ? "green" : "amber"}>
                    {svc.status}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div style={{ borderTop: "1px solid var(--line)", paddingTop: "14px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: "11px", color: "var(--faint)", fontFamily: "var(--mono)" }}>
          Heartbeat interval: 5s · WORM sealed
        </span>
        <a href="#/activity" onClick={onClose} className="btn sm primary" style={{ textDecoration: "none" }}>
          View Live Activity Stream →
        </a>
      </div>
    </Modal>
  );
}
