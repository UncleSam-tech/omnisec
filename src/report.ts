import { UnifiedThreatReport } from './types.js';
import { fetchVirusTotal } from './sources/virustotal.js';
import { fetchGreyNoise } from './sources/greynoise.js';
import { fetchAbuseIPDB } from './sources/abuseipdb.js';
import { fetchPulsedive } from './sources/pulsedive.js';
import { normalizeData } from './enrichment/normalizer.js';
import { getCache, setCache } from './enrichment/cache.js';

export async function generateOmniSecReport(ip: string): Promise<UnifiedThreatReport> {
  const start = Date.now();
  const cached = getCache(ip);
  if (cached) {
    cached.caching.hit = true;
    cached.caching.latencyMs = Date.now() - start;
    return cached;
  }

  const vtKey = process.env.VIRUSTOTAL_API_KEY;
  const gnKey = process.env.GREYNOISE_API_KEY;
  const abuseKey = process.env.ABUSEIPDB_API_KEY;
  const pdKey = process.env.PULSEDIVE_API_KEY;

  if (!vtKey && !gnKey && !abuseKey && !pdKey) {
    throw new Error("No proprietary API keys found in .env! OmniSec requires at least one provider key.");
  }

  const [vtData, gnData, abuseData, pulsediveData] = await Promise.all([
    fetchVirusTotal(ip, vtKey),
    fetchGreyNoise(ip, gnKey),
    fetchAbuseIPDB(ip, abuseKey),
    fetchPulsedive(ip, pdKey)
  ]);

  const report = normalizeData(ip, vtData, gnData, abuseData, pulsediveData, false, Date.now() - start);
  setCache(ip, report);
  return report;
}
