import { UnifiedThreatReport } from '../types.js';

export function normalizeData(ip: string, vtData: any, gnData: any, abuseData: any, pdData: any, isCached: boolean, cachedLatency: number = 0): UnifiedThreatReport {
  let riskScore = 0;
  let maliciousVotes = 0;
  let totalVotes = 0;
  const knownTags: string[] = [];
  const vendorsFlagged: string[] = [];
  
  let isp = 'Unknown';
  let country = 'Unknown';
  let lastSeen = new Date().toISOString();

  let greyNoiseClassification = undefined;
  let abuseConfidenceScore = undefined;
  let pulsediveRisk = undefined;

  // VirusTotal
  if (vtData?.data?.attributes) {
    const attrs = vtData.data.attributes;
    if (attrs.last_analysis_stats) {
      maliciousVotes = attrs.last_analysis_stats.malicious || 0;
      const harmless = attrs.last_analysis_stats.harmless || 0;
      const undetected = attrs.last_analysis_stats.undetected || 0;
      totalVotes = maliciousVotes + harmless + undetected;
    }
    if (maliciousVotes > 0) {
      riskScore += (maliciousVotes * 5); 
      vendorsFlagged.push(`VirusTotal flagged by ${maliciousVotes} vendors`);
    }
    if (attrs.tags && Array.isArray(attrs.tags)) knownTags.push(...attrs.tags);
    if (attrs.as_owner) isp = attrs.as_owner;
    if (attrs.country) country = attrs.country;
  }

  // GreyNoise
  if (gnData) {
    greyNoiseClassification = gnData.classification;
    if (gnData.name) knownTags.push(`GreyNoise Actor: ${gnData.name}`);
    if (gnData.classification === 'malicious') riskScore += 40;
    if (gnData.classification === 'benign') riskScore = Math.max(0, riskScore - 50);
  }

  // AbuseIPDB
  if (abuseData) {
    abuseConfidenceScore = abuseData.abuseConfidenceScore;
    if (abuseConfidenceScore) {
      riskScore += (abuseConfidenceScore * 0.5); // Max 50 points from AbuseIPDB
    }
    if (abuseData.domain) knownTags.push(`Domain: ${abuseData.domain}`);
    if (isp === 'Unknown' && abuseData.isp) isp = abuseData.isp;
    if (country === 'Unknown' && abuseData.countryCode) country = abuseData.countryCode;
  }

  // Pulsedive
  if (pdData) {
    pulsediveRisk = pdData.risk;
    if (pulsediveRisk === 'critical') riskScore += 50;
    else if (pulsediveRisk === 'high') riskScore += 30;
    else if (pulsediveRisk === 'medium') riskScore += 15;
    else if (pulsediveRisk === 'low') riskScore += 5;
    else if (pulsediveRisk === 'none') riskScore = Math.max(0, riskScore - 10);
  }

  riskScore = Math.floor(Math.max(0, Math.min(riskScore, 100)));

  // A-F Risk Grading
  let riskGrade: "A" | "B" | "C" | "D" | "E" | "F" = "A";
  let recommendation = "Safe to connect. No threat detected by provided sources.";

  if (riskScore >= 75 || pulsediveRisk === 'critical') {
    riskGrade = "F";
    recommendation = "CRITICAL RISK: Do not connect. Target explicitly flagged as malicious across enterprise definitions.";
  } else if (riskScore >= 50 || pulsediveRisk === 'high') {
    riskGrade = "D";
    recommendation = "WARNING: Suspicious indicators found. Connect with extreme caution. Likely an open proxy or threat.";
  } else if (riskScore >= 20 || pulsediveRisk === 'medium') {
    riskGrade = "C";
    recommendation = "CAUTION: Minor flags detected. Likely spam or low-level internet background noise.";
  } else if (riskScore > 0 || pulsediveRisk === 'low') {
    riskGrade = "B";
    recommendation = "INFO: Generally safe, but some minor historical activity observed.";
  }

  const noDataFound = !vtData && !gnData && (!abuseData || abuseData.totalReports === 0) && (!pdData || pulsediveRisk === 'unknown');

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
      pulsediveRisk,
      isp,
      country,
      lastSeen
    },
    caching: { hit: isCached, latencyMs: cachedLatency },
    searchExhausted: noDataFound,
    noResultsReason: noDataFound ? "No threat data found across any proprietary platform. Exhausted databases." : "Threat APIs successfully queried and normalized."
  };
}
