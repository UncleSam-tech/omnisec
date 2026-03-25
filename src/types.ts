import { z } from 'zod';

export const threatIndicatorSchema = z.string().describe("The IP address or Domain to analyze");

export const unifiedThreatResultSchema = z.object({
  indicator: z.string(),
  riskScore: z.number().describe("Normalized threat risk from 0 (Safe) to 100 (Critical)"),
  riskGrade: z.enum(["A", "B", "C", "D", "E", "F"]).describe("Enterprise A-F Actionable Risk Score"),
  maliciousVotes: z.number(),
  totalVotes: z.number(),
  knownTags: z.array(z.string()),
  vendorsFlagged: z.array(z.string()),
  greyNoiseClassification: z.string().optional().describe("'noise' (internet scanner) or 'riot' (benign service) from GreyNoise"),
  abuseConfidenceScore: z.number().optional().describe("AbuseIPDB crowdsourced malicious confidence constraint"),
  isp: z.string().optional(),
  country: z.string().optional(),
  lastSeen: z.string().optional()
});

export const unifiedReportSchema = z.object({
  summary: z.string().describe("Executive summary of the normalized findings from all proprietary security APIs"),
  recommendation: z.string().describe("Actionable agent recommendation based on the highest detected risk score"),
  results: unifiedThreatResultSchema,
  caching: z.object({
    hit: z.boolean(),
    latencyMs: z.number()
  }),
  searchExhausted: z.boolean().describe("Critical for Completeness Evaluation: Set to true if both APIs found zero results, ensuring AI agents don't retry execution."),
  noResultsReason: z.string().describe("Reasoning string for AI completeness when searchExhausted is true.")
});

export type UnifiedThreatReport = z.infer<typeof unifiedReportSchema>;
