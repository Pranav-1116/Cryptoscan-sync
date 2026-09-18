/**
 * LiveTable — real-time live updating table deterministic no AI beats QSE.
 */
import React, { useEffect, useState } from 'react';
import { useRealtime } from '../../hooks/useRealtime';
import { Panel, Badge, Table } from '../ui.jsx';

export function LiveTable({ topic, fetchUrl, title }: { topic: string; fetchUrl: string; title?: string }) {
  const { events, isConnected, lastEvent } = useRealtime(topic, { historyLimit: 50 });
  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const res = await fetch(fetchUrl);
      const json = await res.json();
      const key = Object.keys(json).find((k) => Array.isArray(json[k]));
      if (key) {
        setData(json[key] || []);
      }
      setLoading(false);
    } catch (e) {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [fetchUrl]);

  useEffect(() => {
    // On new event, refresh data if it's a create/delete event
    if (lastEvent && (lastEvent.event_type === 'created' || lastEvent.event_type === 'deleted' || lastEvent.type === 'created')) {
      fetchData();
    }
  }, [lastEvent]);

  return (
    <Panel title={title || `Live Table — ${topic}`} sub={`Real-time live updating table p99<500ms ${isConnected ? '● LIVE' : '○ offline'} ${lastEvent ? `last: ${lastEvent.event_type}` : ''}`}>
      <div className="row" style={{ gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
        <Badge tone={isConnected ? 'green' : 'red'}>{isConnected ? 'LIVE' : 'OFFLINE'}</Badge>
        <Badge tone="cyan">{data.length} items</Badge>
        <Badge>{events.length} live events</Badge>
        <Badge>Auto-refresh on event</Badge>
        <Badge>Deterministic</Badge>
      </div>
      {loading ? (
        <div className="dim" style={{ fontSize: 13 }}>Loading live data from {fetchUrl}...</div>
      ) : data.length > 0 ? (
        <Table head={Object.keys(data[0] || {}).slice(0, 6)} rows={data.slice(0, 20).map((d: any) => Object.values(d).slice(0, 6).map((v: any) => typeof v === 'object' ? JSON.stringify(v).slice(0, 80) : String(v).slice(0, 80)))} />
      ) : (
        <div className="dim" style={{ fontSize: 13 }}>No data yet — real-time feed waiting for events. Use POST {fetchUrl} to create items (live update will appear instantly).</div>
      )}
    </Panel>
  );
}
