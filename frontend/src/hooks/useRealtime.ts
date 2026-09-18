/**
 * useRealtime hook — deterministic no AI beats QSE.
 * Provides real-time live updates for any router/topic.
 */
import { useEffect, useState, useCallback, useRef } from 'react';
import { realtimeManager, RealtimeEvent } from '../realtime/RealtimeManager';

export function useRealtime(topic: string, options: { autoConnect?: boolean; historyLimit?: number } = {}) {
  const [events, setEvents] = useState<RealtimeEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [lastEvent, setLastEvent] = useState<RealtimeEvent | null>(null);
  const [stats, setStats] = useState(() => realtimeManager.getStats());
  const historyLimit = options.historyLimit || 100;

  useEffect(() => {
    // Load initial history
    const history = realtimeManager.getHistory(topic, historyLimit);
    setEvents(history);
    if (history.length > 0) {
      setLastEvent(history[history.length - 1]);
    }

    // Subscribe to real-time events
    const unsubscribe = realtimeManager.subscribe(topic, (event) => {
      setEvents((prev) => {
        const newEvents = [...prev, event];
        if (newEvents.length > historyLimit) {
          return newEvents.slice(-historyLimit);
        }
        return newEvents;
      });
      setLastEvent(event);
      setStats(realtimeManager.getStats());
      setIsConnected(realtimeManager.isConnected(topic));
    });

    // Check connection status periodically
    const interval = setInterval(() => {
      setIsConnected(realtimeManager.isConnected(topic));
      setStats(realtimeManager.getStats());
    }, 2000);

    return () => {
      unsubscribe();
      clearInterval(interval);
    };
  }, [topic, historyLimit]);

  const publish = useCallback((eventType: string, data: any = {}) => {
    realtimeManager.publish(topic, eventType, data);
  }, [topic]);

  const clear = useCallback(() => {
    setEvents([]);
    setLastEvent(null);
  }, []);

  return {
    events,
    lastEvent,
    isConnected,
    stats,
    publish,
    clear,
    live: true,
    deterministic: true,
  };
}

export function useGlobalRealtime(options: { historyLimit?: number } = {}) {
  const [events, setEvents] = useState<RealtimeEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [lastEvent, setLastEvent] = useState<RealtimeEvent | null>(null);
  const historyLimit = options.historyLimit || 200;

  useEffect(() => {
    const history = realtimeManager.getHistory(undefined, historyLimit);
    setEvents(history);
    if (history.length > 0) {
      setLastEvent(history[history.length - 1]);
    }

    const unsubscribe = realtimeManager.subscribeGlobal((event) => {
      setEvents((prev) => {
        const newEvents = [...prev, event];
        if (newEvents.length > historyLimit) {
          return newEvents.slice(-historyLimit);
        }
        return newEvents;
      });
      setLastEvent(event);
      setIsConnected(realtimeManager.isConnected('global'));
    });

    const interval = setInterval(() => {
      setIsConnected(realtimeManager.isConnected('global'));
    }, 2000);

    return () => {
      unsubscribe();
      clearInterval(interval);
    };
  }, [historyLimit]);

  return {
    events,
    lastEvent,
    isConnected,
    live: true,
    deterministic: true,
  };
}
