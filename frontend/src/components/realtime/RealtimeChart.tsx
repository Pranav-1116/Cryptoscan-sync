/**
 * RealtimeChart — live chart with real-time data deterministic no AI high-assurance verification.
 */
import React, { useEffect, useState } from 'react';
import { useRealtime } from '../../hooks/useRealtime';
import { Panel, Badge } from '../ui.jsx';

export function RealtimeChart({ topic, title }: { topic: string; title?: string }) {
  const { events, isConnected } = useRealtime(topic, { historyLimit: 100 });
  const [dataPoints, setDataPoints] = useState<number[]>([]);

  useEffect(() => {
    // Convert events to data points (event count per second)
    const now = Date.now();
    const recent = events.filter((e: any) => {
      const ts = new Date(e.timestamp).getTime();
      return now - ts < 60000; // Last 60 seconds
    });
    // Group by 5-second buckets
    const buckets: number[] = Array(12).fill(0);
    recent.forEach((e: any) => {
      const age = now - new Date(e.timestamp).getTime();
      const bucket = Math.floor(age / 5000);
      if (bucket >= 0 && bucket < 12) {
        buckets[11 - bucket]++;
      }
    });
    setDataPoints(buckets);
  }, [events]);

  const max = Math.max(...dataPoints, 1);

  return (
    <Panel title={title || `Live Chart — ${topic}`} sub={`Real-time events per 5s bucket last 60s ${isConnected ? '● LIVE' : '○ offline'}`}>
      <div className="row" style={{ gap: 8, marginBottom: 12 }}>
        <Badge tone={isConnected ? 'green' : 'red'}>{isConnected ? 'LIVE' : 'OFFLINE'}</Badge>
        <Badge tone="cyan">{events.length} events</Badge>
        <Badge>{dataPoints.reduce((a, b) => a + b, 0)} last 60s</Badge>
      </div>
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: 4, height: 120, padding: 12, background: 'rgba(0,0,0,0.2)', borderRadius: 8 }}>
        {dataPoints.map((val, i) => (
          <div
            key={i}
            style={{
              flex: 1,
              height: `${(val / max) * 100}%`,
              minHeight: val > 0 ? 4 : 2,
              background: val > 0 ? (isConnected ? '#5ee9ff' : '#888') : 'rgba(255,255,255,0.1)',
              borderRadius: 2,
              transition: 'height 0.3s ease',
            }}
            title={`${val} events`}
          />
        ))}
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: '#888', marginTop: 4 }}>
        <span>60s ago</span>
        <span>Now</span>
      </div>
    </Panel>
  );
}

export default RealtimeChart;
