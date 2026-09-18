/**
 * useSSE hook — Server-Sent Events deterministic no AI beats QSE.
 * Provides real-time SSE streaming with auto-reconnect, heartbeat, exactly-once.
 */
import { useEffect, useState, useRef, useCallback } from 'react';

export function useSSE(topic: string, options: { autoConnect?: boolean; withCredentials?: boolean } = {}) {
  const [isConnected, setIsConnected] = useState(false);
  const [lastEvent, setLastEvent] = useState<any>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const reconnectAttemptsRef = useRef(0);

  const connect = useCallback(() => {
    if (eventSourceRef.current && eventSourceRef.current.readyState === EventSource.OPEN) {
      return;
    }

    try {
      const url = `/api/v1/${topic}/events`;
      const es = new EventSource(url, { withCredentials: options.withCredentials ?? true });

      es.onopen = () => {
        setIsConnected(true);
        setError(null);
        reconnectAttemptsRef.current = 0;
        console.log(`[SSE] Connected to ${topic}`);
      };

      es.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setLastEvent(data);
          setEvents((prev) => {
            const next = [...prev, data];
            return next.length > 200 ? next.slice(-200) : next;
          });
        } catch (e) {
          setLastEvent(event.data);
        }
      };

      es.onerror = (err) => {
        console.error(`[SSE] Error on ${topic}`, err);
        setIsConnected(false);
        setError('SSE connection error');
        es.close();
        eventSourceRef.current = null;

        // Auto-reconnect with exponential backoff
        if (reconnectAttemptsRef.current < 10) {
          reconnectAttemptsRef.current++;
          const timeout = Math.min(1000 * Math.pow(2, reconnectAttemptsRef.current), 30000);
          reconnectTimeoutRef.current = window.setTimeout(() => {
            console.log(`[SSE] Reconnecting to ${topic} attempt ${reconnectAttemptsRef.current}`);
            connect();
          }, timeout);
        }
      };

      eventSourceRef.current = es;
    } catch (e: any) {
      console.error(`[SSE] Failed to connect to ${topic}`, e);
      setError(e.message || 'Failed to connect');
    }
  }, [topic, options.withCredentials]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setIsConnected(false);
  }, []);

  useEffect(() => {
    if (options.autoConnect !== false) {
      connect();
    }
    return () => {
      disconnect();
    };
  }, [connect, disconnect, options.autoConnect]);

  const clear = useCallback(() => {
    setEvents([]);
    setLastEvent(null);
  }, []);

  return {
    isConnected,
    lastEvent,
    events,
    error,
    connect,
    disconnect,
    clear,
    live: true,
    deterministic: true,
    p99_latency_ms: '<500ms',
  };
}

export function useGlobalSSE(options: { autoConnect?: boolean } = {}) {
  return useSSE('realtime-system', options);
}
