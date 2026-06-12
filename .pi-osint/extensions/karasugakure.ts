/**
 * Karasugakure OSINT Agent Extension for Pi-OSINT
 * Exposes Karasugakure CLI commands as native Pi-OSINT tools.
 */

import { Type } from "@earendil-works/pi-ai";
import { defineTool, type ExtensionAPI } from "@earendil-works/pi-coding-agent";

// Helper to run python CLI in .venv
async function runKarasu(pi: ExtensionAPI, args: string[], signal?: AbortSignal) {
	try {
		const res = await pi.exec("./.venv/bin/karasu", args, { signal });
		if (res.code === 0) {
			return {
				content: [{ type: "text" as const, text: res.stdout }],
				details: { success: true, stdout: res.stdout }
			};
		} else {
			return {
				content: [{ type: "text" as const, text: `Error: CLI exited with code ${res.code}.\nStderr: ${res.stderr}\nStdout: ${res.stdout}` }],
				details: { success: false, code: res.code, stderr: res.stderr }
			};
		}
	} catch (err: any) {
		return {
			content: [{ type: "text" as const, text: `Failed to execute karasu: ${err.message || err}` }],
			details: { success: false, error: String(err) }
		};
	}
}

// 1. Recon Tool
const reconTool = defineTool({
	name: "karasu_recon",
	label: "Karasu Recon",
	description: "Run infrastructure and surface reconnaissance on a domain or IP (Heimdall).",
	parameters: Type.Object({
		target: Type.String({ description: "Target domain or IP address" }),
	}),
	async execute(_toolCallId, params, signal) {
		return runKarasu(this.api, ["recon", params.target], signal);
	}
});

// 2. Humint Tool
const humintTool = defineTool({
	name: "karasu_humint",
	label: "Karasu Humint",
	description: "Scan identity, profiles, and digital footprint for an alias/username (Loki).",
	parameters: Type.Object({
		username: Type.String({ description: "Target username or alias" }),
	}),
	async execute(_toolCallId, params, signal) {
		return runKarasu(this.api, ["humint", params.username], signal);
	}
});

// 3. Darkweb Tool
const darkwebTool = defineTool({
	name: "karasu_darkweb",
	label: "Karasu Darkweb",
	description: "Query darkweb onion forums, leak databases, and marketplaces (Hel).",
	parameters: Type.Object({
		query: Type.String({ description: "Leak keyword or search query" }),
	}),
	async execute(_toolCallId, params, signal) {
		return runKarasu(this.api, ["darkweb", params.query], signal);
	}
});

// 4. Correlate Tool
const correlateTool = defineTool({
	name: "karasu_correlate",
	label: "Karasu Correlate",
	description: "Execute link correlation and relational analysis on active nodes (Fenrir).",
	parameters: Type.Object({}),
	async execute(_toolCallId, _params, signal) {
		return runKarasu(this.api, ["correlate"], signal);
	}
});

// 5. Graph Query Tool
const graphQueryTool = defineTool({
	name: "karasu_graph_query",
	label: "Karasu Graph Query",
	description: "Query the relational graph using natural language or Cypher statements (Norn + Mimir).",
	parameters: Type.Object({
		query: Type.String({ description: "Search intent or Cypher query statement" }),
	}),
	async execute(_toolCallId, params, signal) {
		return runKarasu(this.api, ["graph", "query", params.query], signal);
	}
});

// 6. Report Tool
const reportTool = defineTool({
	name: "karasu_report",
	label: "Karasu Report",
	description: "Generate a markdown investigation dossier summarizing validated connections.",
	parameters: Type.Object({}),
	async execute(_toolCallId, _params, signal) {
		return runKarasu(this.api, ["report"], signal);
	}
});

export default function (pi: ExtensionAPI) {
	pi.registerTool(reconTool);
	pi.registerTool(humintTool);
	pi.registerTool(darkwebTool);
	pi.registerTool(correlateTool);
	pi.registerTool(graphQueryTool);
	pi.registerTool(reportTool);
}
