import { UnifiedThreatReport } from '../types.js';

export function normalizeData(ip: string, vtData: any, gnData: any, abuseData: any, isCached: boolean, cachedLatency: number = 0): UnifiedThreatReport {
  let riskScore = 0;
  let maliciousVotes = 0;
  let totalVotes = 0;
  const knownTags: string[] = [];
  const vendorsFlagged: string[] = [];
  
  let isp = 'Unknown';
  let country = 'Unknown';
  let greyNoiseClassification = 'unknown';
  let abuseConfidenceScore = 0;

  if (vtData?.data?.attributes) {
    const attrs = vtData.data.attributes;
    if (attrs.last_analysis_stats) {
      maliciousVotes = attrs.last_analysis_stats.malicious || 0;
      const harmless = attrs.last_analysis_stats.harmless || 0;
      const undetected = attrs.last_analysis_stats.undetected || 0;
      totalVotes = maliciousVotes + harmless + undetected;
    }
    
    if (maliciousVotes > 0) {
      riskScore += (maliciousVotes * 6); 
      vendorsFlagged.push(`VirusTotal flagged by ${maliciousVotes} vendors`);
    }
    if (attrs.tags && Array.isArray(attrs.tags)) {
      knownTags.push(...attrs.tags);
    }
    if (attrs.as_owner) isp = attrs.as_owner;
    if (attrs.country) country = attrs.country;
  }

  if (gnData) {
    if (gnData.name) knownTags.push(gnData.name);
    if (gnData.classification) {
      greyNoiseClassification = gnData.classification;
      if (gnData.classification === 'riot') {
        riskScore = Math.max(0, riskScore - 20); // Benign
      } else if (gnData.classification === 'malicious') {
        riskScore += 25; // Known bad actor
      }
    }
  }

  if (abuseData) {
    if (abuseData.abuseConfidenceScore) {
      abuseConfidenceScore = abuseData.abuseConfidenceScore;
      riskScore += (abuseData.abuseConfidenceScore * 0.4); 
    }
    if (abuseData.isp && isp === 'Unknown') isp = abuseData.isp;
    if (abuseData.countryCode && country === 'Unknown') country = abuseData.countryCode;
    if (abuseData.domain) knownTags.push(`Domain: ${abuseData.domain}`);
  }

  riskScore = Math.floor(Math.min(riskScore, 100));

  let riskGrade: "A" | "B" | "C" | "D" | "E" | "F" = "A";
  if (riskScore >= 90) riskGrade = "F";
  else if (riskScore >= 75) riskGrade = "E";
  else if (riskScore >= 50) riskGrade = "D";
  else if (riskScore >= 30) riskGrade = "C";
  else if (riskScore >= 10) riskGrade = "B";

  let recommendation = "Safe to connect. A-Grade target.";
  if (riskGrade === "F" || riskGrade === "E") recommendation = `CRITICAL RISK (${riskGrade}): Do not connect. High probability of malicious activity.`;
  else if (riskGrade === "D" || riskGrade === "C") recommendation = `WARNING (${riskGrade}): Suspicious indicators found. Connect with extreme caution.`;

  const noDataFound = (!vtData || !vtData.data) && !gnData && (!abuseData || abuseData.totalReports === 0);

  return {
    summary: `OmniSec Unified Intelligence for ${ip}: Actionable Risk Grade [${riskGrade}]. Risk Score: ${riskScore}/100.`,
    recommendation,
    results: {
      indicator: ip,
      riskScore,
      riskGrade,
      maliciousVotes,
      totalVotes,
      knownTags: [...new Set(knownTags)],
      vendorsFlagged,
      greyNoiseClassification,
      abuseConfidenceScore,
      isp,
      country,
      lastSeen: new Date().toISOString()
    },
    caching: {
      hit: isCached,
      latencyMs: cachedLatency
    },
    searchExhausted: noDataFound,
    noResultsReason: noDataFound ? "No threat data found across VirusTotal, GreyNoise, or AbuseIPDB. AI search definitively exhausted." : "Proprietary threat APIs successfully queried and normalized."
  };
}
