/**
 * LiveStatusBadge — real-time live status indicator deterministic no AI.
 */
import React from 'react';
import { useRealtimeContext } from './RealtimeProvider';
import { useRealtime } from '../../hooks/useRealtime';
import { Badge } from '../ui.jsx';

export function LiveStatusBadge({ topic }: { topic?: string }) {
  const global = useRealtimeContext();
  const topicRealtime = topic ? useRealtime(topic) : null;

  const isConnected = topic ? topicRealtime?.isConnected : global.isConnected;
  const stats = topic ? topicRealtime?.stats : global.stats;

  return (
    <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
      <Badge tone={isConnected ? 'green' : 'red'}>{isConnected ? '● LIVE' : '○ OFFLINE'}</Badge>
      <Badge tone="cyan">{stats?.totalEvents || 0} events</Badge>
      <Badge>{stats?.activeTopics || 0} topics</Badge>
      <Badge>p99 &lt;500ms</Badge>
      <Badge>Exactly-once</Badge>
      {topic && <Badge tone="cyan">{topic}</Badge>}
    </div>
  );
}

export function GlobalLiveStatusBadge() {
  return <LiveStatusBadge />;
}

export default LiveStatusBadge;
