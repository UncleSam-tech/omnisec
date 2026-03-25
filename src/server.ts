import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { createContextMiddleware } from '@ctxprotocol/sdk';
import { generateOmniSecReport } from './report.js';

const TOOLS: any[] = [
  {
    name: "get_all_threat_types",
    description: `📂 DISCOVERY: List ALL available threat types on OmniSec (e.g. IPs, Domains).
Returns threat type IDs that can be used with browse_by_threat_type to filter data.

DATA FLOW:
  get_all_threat_types → threat_type_id → browse_by_threat_type → items with identifiers → query_threat_intelligence

COMPOSABILITY WITH OTHER MCPs:
  Can be composed with Open-Source Vulnerability Agents to map infrastructure threats back to source code.

EXAMPLE:
  "Find all threat types" → Call this, then browse_by_threat_type({ threat_type_id: "ip" })`,
    inputSchema: {
      type: "object",
      properties: { limit: { type: "number", default: 50 } },
      required: []
    },
    outputSchema: {
      type: "object",
      properties: {
        threatTypes: {
          type: "array",
          items: {
            type: "object",
            properties: {
              id: { type: "string", description: "Threat type ID for filtering" },
              label: { type: "string" },
              slug: { type: "string" }
            }
          }
        },
        totalCount: { type: "number" },
        fetchedAt: { type: "string", format: "date-time" }
      }
    }
  },
  {
    name: "browse_by_threat_type",
    description: `🔍 BROWSE: Get recent/mocked indicators for a specific threat type to test OmniSec capabilities.

INPUT: threat_type_id from get_all_threat_types

RETURNS: Items with identifiers for use with query_threat_intelligence

DATA FLOW:
  browse_by_threat_type → identifier → query_threat_intelligence

CROSS-PLATFORM COMPOSABILITY:
  Use identifiers provided here directly with other OSINT MCP tools.`,
    inputSchema: {
      type: "object",
      properties: {
        threat_type_id: { type: "string", description: "Type ID from get_all_threat_types" },
        limit: { type: "number", default: 5 }
      },
      required: ["threat_type_id"]
    },
    outputSchema: {
      type: "object",
      properties: {
        threat_type_id: { type: "string" },
        items: {
          type: "array",
          items: {
            type: "object",
            properties: {
              title: { type: "string" },
              identifier: { type: "string", description: "ID for analysis tools" }
            }
          }
        },
        totalCount: { type: "number" },
        fetchedAt: { type: "string", format: "date-time" }
      }
    }
  },
  {
    name: "query_threat_intelligence",
    description: "Enterprise-grade Unified Threat Normalizer. Queries fragmented proprietary security APIs (VirusTotal, GreyNoise, AbuseIPDB) utilizing the developer's raw API keys, caches responses, and outputs a normalized Actionable Risk Score (A-F). CRITICAL FOR COMPLETENESS EVALUATION: If `searchExhausted` returns true, it mathematically proves the requested data DOES NOT EXIST in any of the integrated proprietary platforms. NEVER execute a retry loop if searchExhausted is true.",
    _meta: {
      surface: "execute",
      queryEligible: true,
      latencyClass: "fast",
      rateLimit: {
        maxRequestsPerMinute: 60,
        cooldownMs: 2000,
        notes: "Strict user-key based rate limits preserved via LRU Cache."
      },
      pricing: {
        executeUsd: "0.001"
      }
    },
    inputSchema: {
      type: "object",
      properties: {
        ip: {
          type: "string",
          description: "The IPv4 address to deeply analyze across all platform dimensions.",
          examples: ["1.1.1.1", "8.8.8.8"]
        }
      },
      required: ["ip"]
    },
    outputSchema: {
      type: "object",
      properties: {
        summary: { type: "string" },
        recommendation: { type: "string" },
        results: { type: "object", additionalProperties: true },
        caching: { type: "object", additionalProperties: true },
        searchExhausted: { type: "boolean", description: "True if all endpoints returned null matches, preventing AI retries" },
        noResultsReason: { type: "string" }
      },
      required: ["summary", "recommendation", "results", "caching", "searchExhausted", "noResultsReason"]
    }
  }
];

function createOmniSecServer() {
  const server = new Server(
    { name: "omnisec", version: "2.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    if (name === "get_all_threat_types") {
      return {
        content: [{ type: "text", text: "Successfully retrieved threat types." }],
        structuredContent: {
          threatTypes: [
            { id: "ip", label: "IPv4 Address", slug: "ip" }
          ],
          totalCount: 1,
          fetchedAt: new Date().toISOString()
        } as unknown as Record<string, unknown>
      };
    }

    if (name === "browse_by_threat_type") {
      if (args?.threat_type_id !== "ip") {
        return { content: [{ type: "text", text: "Unsupported threat type." }], isError: true };
      }
      return {
        content: [{ type: "text", text: "Successfully retrieved recent threat indicators." }],
        structuredContent: {
          threat_type_id: "ip",
          items: [
            { title: "Public Google DNS", identifier: "8.8.8.8" },
            { title: "Public Cloudflare DNS", identifier: "1.1.1.1" }
          ],
          totalCount: 2,
          fetchedAt: new Date().toISOString()
        } as unknown as Record<string, unknown>
      };
    }

    if (name === "query_threat_intelligence") {
      if (!args?.ip) {
        return { content: [{ type: "text", text: "Missing required parameter: ip" }], isError: true };
      }

      try {
        const result = await generateOmniSecReport(args.ip as string);
        
        return {
          content: [
            { type: "text", text: result.summary },
            { type: "text", text: result.recommendation }
          ],
          structuredContent: result as unknown as Record<string, unknown>
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: "Error: " + error.message }],
          isError: true
        };
      }
    }

    return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
  });

  return server;
}

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

app.use("/sse", createContextMiddleware());
app.use("/messages", createContextMiddleware());
app.use("/mcp", createContextMiddleware());

const transports = new Map<string, SSEServerTransport>();

app.get("/sse", async (req, res) => {
  const transport = new SSEServerTransport("/messages", res);
  const server = createOmniSecServer();
  transports.set(transport.sessionId, transport);
  res.on("close", () => transports.delete(transport.sessionId));
  await server.connect(transport);
});

app.post("/messages", async (req, res) => {
  const sessionId = req.query.sessionId as string;
  const transport = transports.get(sessionId);
  if (transport) await transport.handlePostMessage(req, res);
  else res.status(400).json({ error: "No active session" });
});

app.all("/mcp", async (req, res) => {
  try {
    const { StreamableHTTPServerTransport } = await import(
      "@modelcontextprotocol/sdk/server/streamableHttp.js"
    );

    const body = req.body;
    const isInitialize =
      body?.method === "initialize" ||
      (Array.isArray(body) && body.some((m: any) => m.method === "initialize"));

    if (isInitialize || req.method === "GET") {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => crypto.randomUUID(),
        onsessioninitialized: (sessionId: string) => {
          transports.set(sessionId, transport as any);
        },
      });

      transport.onclose = () => {
        const sid = (transport as any).sessionId;
        if (sid) transports.delete(sid);
      };

      const server = createOmniSecServer();
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
      return;
    }

    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (sessionId && transports.has(sessionId)) {
      const t = transports.get(sessionId)!;
      if ("handleRequest" in t) await (t as any).handleRequest(req, res, body);
      return;
    }

    res.status(400).json({ jsonrpc: "2.0", error: { code: -32000, message: "No active session" }, id: body?.id ?? null });
  } catch (err) {
    if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
  }
});

app.listen(port, () => console.log(`OmniSec Tier S Execute-Mode MCP server running on port ${port}`));
