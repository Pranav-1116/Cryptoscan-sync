/**
 * RealtimeProvider — deterministic no AI beats QSE.
 * Provides global real-time context, WebSocket manager, live status.
 */
import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { realtimeManager, RealtimeEvent } from '../../realtime/RealtimeManager';

type RealtimeContextType = {
  isConnected: boolean;
  globalEvents: RealtimeEvent[];
  lastGlobalEvent: RealtimeEvent | null;
  stats: any;
  connect: (topic: string) => void;
  disconnect: (topic: string) => void;
  publish: (topic: string, eventType: string, data?: any) => void;
  live: boolean;
  deterministic: boolean;
};

const RealtimeContext = createContext<RealtimeContextType | null>(null);

export function RealtimeProvider({ children }: { children: ReactNode }) {
  const [isConnected, setIsConnected] = useState(false);
  const [globalEvents, setGlobalEvents] = useState<RealtimeEvent[]>([]);
  const [lastGlobalEvent, setLastGlobalEvent] = useState<RealtimeEvent | null>(null);
  const [stats, setStats] = useState(() => realtimeManager.getStats());

  useEffect(() => {
    // Connect to global
    realtimeManager.connect('global');

    const unsubscribe = realtimeManager.subscribeGlobal((event) => {
      setGlobalEvents((prev) => {
        const next = [...prev, event];
        return next.length > 200 ? next.slice(-200) : next;
      });
      setLastGlobalEvent(event);
      setStats(realtimeManager.getStats());
      setIsConnected(realtimeManager.isConnected('global'));
    });

    const interval = setInterval(() => {
      setStats(realtimeManager.getStats());
      setIsConnected(realtimeManager.isConnected('global'));
    }, 3000);

    return () => {
      unsubscribe();
      clearInterval(interval);
    };
  }, []);

  const connect = (topic: string) => {
    realtimeManager.connect(topic);
  };

  const disconnect = (topic: string) => {
    realtimeManager.disconnect(topic);
  };

  const publish = (topic: string, eventType: string, data: any = {}) => {
    realtimeManager.publish(topic, eventType, data);
  };

  return (
    <RealtimeContext.Provider value={{ isConnected, globalEvents, lastGlobalEvent, stats, connect, disconnect, publish, live: true, deterministic: true }}>
      {children}
    </RealtimeContext.Provider>
  );
}

export function useRealtimeContext() {
  const ctx = useContext(RealtimeContext);
  if (!ctx) {
    throw new Error('useRealtimeContext must be used within RealtimeProvider');
  }
  return ctx;
}
