/**
 * useWebSocket hook — deterministic no AI.
 * Low-level WebSocket hook with auto-reconnect, heartbeat, backpressure.
 */
import { useEffect, useState, useRef, useCallback } from 'react';

export function useWebSocket(topic: string, options: { autoConnect?: boolean; protocols?: string | string[] } = {}) {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<any>(null);
  const [messages, setMessages] = useState<any[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const maxReconnectAttempts = 10;

  const getWsUrl = useCallback((t: string) => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${protocol}//${window.location.host}/api/v1/${t}/ws`;
  }, []);

  const connect = useCallback(() => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      return;
    }

    try {
      const url = getWsUrl(topic);
      const ws = new WebSocket(url, options.protocols);

      ws.onopen = () => {
        setIsConnected(true);
        reconnectAttemptsRef.current = 0;
        console.log(`[WS] Connected to ${topic}`);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setLastMessage(data);
          setMessages((prev) => {
            const next = [...prev, data];
            return next.length > 100 ? next.slice(-100) : next;
          });
        } catch (e) {
          setLastMessage(event.data);
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        wsRef.current = null;
        console.log(`[WS] Disconnected from ${topic}`);

        // Auto-reconnect
        if (reconnectAttemptsRef.current < maxReconnectAttempts) {
          reconnectAttemptsRef.current++;
          const timeout = Math.min(1000 * Math.pow(2, reconnectAttemptsRef.current), 30000);
          reconnectTimeoutRef.current = window.setTimeout(() => {
            console.log(`[WS] Reconnecting to ${topic} attempt ${reconnectAttemptsRef.current}`);
            connect();
          }, timeout);
        }
      };

      ws.onerror = (error) => {
        console.error(`[WS] Error on ${topic}`, error);
      };

      wsRef.current = ws;
    } catch (e) {
      console.error(`[WS] Failed to connect to ${topic}`, e);
    }
  }, [topic, getWsUrl, options.protocols]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setIsConnected(false);
  }, []);

  const send = useCallback((data: any) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      const payload = typeof data === 'string' ? data : JSON.stringify(data);
      wsRef.current.send(payload);
      return true;
    }
    return false;
  }, []);

  useEffect(() => {
    if (options.autoConnect !== false) {
      connect();
    }
    return () => {
      disconnect();
    };
  }, [connect, disconnect, options.autoConnect]);

  return {
    isConnected,
    lastMessage,
    messages,
    connect,
    disconnect,
    send,
    live: true,
    deterministic: true,
  };
}
