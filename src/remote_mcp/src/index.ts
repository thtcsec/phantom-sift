/**
 * Phantom SIFT — Remote MCP Server on Cloudflare Workers
 *
 * Exposes threat intelligence and reporting tools as a Remote MCP server.
 * Deployed at the edge via Cloudflare Workers.
 *
 * Tools exposed:
 * - threat_intel_hash: Look up file hash on VirusTotal
 * - threat_intel_ip: Look up IP reputation (VT + AbuseIPDB)
 * - threat_intel_domain: Look up domain reputation
 * - report_finding: Store a structured finding for the report
 *
 * Architecture role:
 * - Keeps API keys off the SIFT Workstation (secrets in CF Workers)
 * - Provides network-level boundary (agent on SIFT calls remote MCP)
 * - Enables future SOAR bridge: confirmed IOC → trigger cloud remediation
 */

export interface Env {
  VIRUSTOTAL_API_KEY: string;
  ABUSEIPDB_API_KEY: string;
  ENVIRONMENT: string;
}

// MCP Tool definitions
interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

interface McpToolCall {
  name: string;
  arguments: Record<string, unknown>;
}

const TOOLS: McpTool[] = [
  {
    name: "threat_intel_hash",
    description:
      "Look up a file hash (MD5/SHA1/SHA256) against VirusTotal. Returns detection ratio and vendor results.",
    inputSchema: {
      type: "object",
      properties: {
        hash: { type: "string", description: "File hash to look up" },
      },
      required: ["hash"],
    },
  },
  {
    name: "threat_intel_ip",
    description:
      "Look up an IP address against VirusTotal and AbuseIPDB for reputation scoring.",
    inputSchema: {
      type: "object",
      properties: {
        ip: { type: "string", description: "IP address to check" },
      },
      required: ["ip"],
    },
  },
  {
    name: "threat_intel_domain",
    description: "Look up a domain against VirusTotal for reputation.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Domain name to check" },
      },
      required: ["domain"],
    },
  },
  {
    name: "report_finding",
    description:
      "Submit a structured forensic finding for inclusion in the final report.",
    inputSchema: {
      type: "object",
      properties: {
        finding_id: { type: "string" },
        title: { type: "string" },
        category: { type: "string" },
        confidence: {
          type: "string",
          enum: ["confirmed", "high", "medium", "low"],
        },
        description: { type: "string" },
        iocs: { type: "array", items: { type: "string" } },
      },
      required: ["finding_id", "title", "category", "confidence"],
    },
  },
];

// Tool handlers
async function handleToolCall(
  call: McpToolCall,
  env: Env
): Promise<Record<string, unknown>> {
  switch (call.name) {
    case "threat_intel_hash":
      return await vtHashLookup(call.arguments.hash as string, env);
    case "threat_intel_ip":
      return await ipLookup(call.arguments.ip as string, env);
    case "threat_intel_domain":
      return await vtDomainLookup(call.arguments.domain as string, env);
    case "report_finding":
      return { status: "stored", finding_id: call.arguments.finding_id };
    default:
      return { error: `Unknown tool: ${call.name}` };
  }
}

async function vtHashLookup(
  hash: string,
  env: Env
): Promise<Record<string, unknown>> {
  try {
    const resp = await fetch(
      `https://www.virustotal.com/api/v3/files/${hash}`,
      { headers: { "x-apikey": env.VIRUSTOTAL_API_KEY } }
    );
    if (!resp.ok) return { error: `VT returned ${resp.status}`, hash };
    const data = (await resp.json()) as Record<string, unknown>;
    const attrs = (data.data as Record<string, unknown>)?.attributes as Record<
      string,
      unknown
    >;
    return {
      source: "virustotal",
      hash,
      stats: attrs?.last_analysis_stats || {},
      meaningful_name: attrs?.meaningful_name || null,
      type_description: attrs?.type_description || null,
    };
  } catch (e) {
    return { error: String(e), hash };
  }
}

async function ipLookup(
  ip: string,
  env: Env
): Promise<Record<string, unknown>> {
  const results: Record<string, unknown>[] = [];

  // VirusTotal
  try {
    const vtResp = await fetch(
      `https://www.virustotal.com/api/v3/ip_addresses/${ip}`,
      { headers: { "x-apikey": env.VIRUSTOTAL_API_KEY } }
    );
    if (vtResp.ok) {
      const data = (await vtResp.json()) as Record<string, unknown>;
      const attrs = (data.data as Record<string, unknown>)
        ?.attributes as Record<string, unknown>;
      results.push({
        source: "virustotal",
        stats: attrs?.last_analysis_stats || {},
      });
    }
  } catch {}

  // AbuseIPDB
  try {
    const abResp = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
      {
        headers: {
          Key: env.ABUSEIPDB_API_KEY,
          Accept: "application/json",
        },
      }
    );
    if (abResp.ok) {
      const data = (await abResp.json()) as Record<string, unknown>;
      results.push({ source: "abuseipdb", data: data.data });
    }
  } catch {}

  return { ip, results };
}

async function vtDomainLookup(
  domain: string,
  env: Env
): Promise<Record<string, unknown>> {
  try {
    const resp = await fetch(
      `https://www.virustotal.com/api/v3/domains/${domain}`,
      { headers: { "x-apikey": env.VIRUSTOTAL_API_KEY } }
    );
    if (!resp.ok) return { error: `VT returned ${resp.status}`, domain };
    const data = (await resp.json()) as Record<string, unknown>;
    const attrs = (data.data as Record<string, unknown>)?.attributes as Record<
      string,
      unknown
    >;
    return {
      source: "virustotal",
      domain,
      stats: attrs?.last_analysis_stats || {},
      registrar: attrs?.registrar || null,
      creation_date: attrs?.creation_date || null,
    };
  } catch (e) {
    return { error: String(e), domain };
  }
}

// Worker entry point — simple HTTP handler for MCP
export default {
  async fetch(
    request: Request,
    env: Env
  ): Promise<Response> {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === "/health") {
      return new Response(
        JSON.stringify({ status: "ok", server: "phantom-sift-mcp" }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // List tools
    if (url.pathname === "/tools" && request.method === "GET") {
      return new Response(JSON.stringify({ tools: TOOLS }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // Execute tool
    if (url.pathname === "/call" && request.method === "POST") {
      const body = (await request.json()) as McpToolCall;
      const result = await handleToolCall(body, env);
      return new Response(JSON.stringify(result), {
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response("Phantom SIFT Remote MCP Server", { status: 200 });
  },
};
