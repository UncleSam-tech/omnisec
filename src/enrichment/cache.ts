import { UnifiedThreatReport } from '../types.js';

interface CacheItem {
  data: UnifiedThreatReport;
  timestamp: number;
}

const cache = new Map<string, CacheItem>();
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour TTL to preserve expensive VT/Shodan quotas
const MAX_CACHE_SIZE = 1000;

export function setCache(key: string, data: UnifiedThreatReport): void {
  if (cache.size >= MAX_CACHE_SIZE) {
    // Basic LRU eviction: Delete the oldest key
    const firstKey = cache.keys().next().value;
    if (firstKey) cache.delete(firstKey);
  }
  cache.set(key, { data, timestamp: Date.now() });
}

export function getCache(key: string): UnifiedThreatReport | null {
  const item = cache.get(key);
  if (!item) return null;
  
  if (Date.now() - item.timestamp > CACHE_TTL_MS) {
    cache.delete(key);
    return null;
  }
  
  return item.data;
}
