/**
 * Common MCP (Model Context Protocol) client infrastructure
 * Provides base classes for implementing MCP clients over different transports
 * Reference: https://modelcontextprotocol.io/specification/2024-11-05
 * Reference: https://modelcontextprotocol.io/specification/2025-03-26
 */

/**
 * Base MCP client class with common JSON-RPC and protocol logic
 */
class McpClient {
	constructor(endpoint, protocolVersion) {
		this.server_endpoint = endpoint;
		this.protocolVersion = protocolVersion;
		this.rpcId = 1;
		this.sessionId = null;
		this.isConnected = false;
	}

	/**
	 * Get next JSON-RPC message ID
	 */
	nextId() {
		return this.rpcId++;
	}

	/**
	 * Create a JSON-RPC 2.0 message
	 */
	jsonrpc(method, params) {
		return {
			jsonrpc: "2.0",
			id: this.nextId(),
			method,
			params: params || {}
		};
	}

	/**
	 * Create a JSON-RPC 2.0 notification (no ID)
	 */
	jsonrpcNotification(method, params) {
		return {
			jsonrpc: "2.0",
			method,
			params: params || {}
		};
	}

	/**
	 * Parse MCP response, handling both plain JSON and SSE format
	 */
	parseMcpResponse(text) {
		let resp;
		
		// Check for SSE format: data: {...} (with or without event: prefix)
		if (text.includes('data: ')) {
			const dataMatch = text.match(/data: (.+)$/m);
			if (dataMatch) {
				try {
					resp = JSON.parse(dataMatch[1]);
				} catch (_e) {
					console.log('Failed to parse SSE data:', dataMatch[1]);
				}
			}
		}
		
		// If not SSE or SSE parsing failed, try plain JSON
		if (!resp) {
			try {
				resp = JSON.parse(text);
			} catch (_e) {
				console.log('Failed to parse as JSON:', text.substring(0, 100));
			}
		}
		
		return resp;
	}

	/**
	 * Initialize MCP session with server
	 */
	async initialize(clientInfo = { name: "singularity", version: "0.0.1" }) {
		console.log('Initializing MCP session...');
		
		const initMessage = this.jsonrpc("initialize", {
			protocolVersion: this.protocolVersion,
			capabilities: {},
			clientInfo
		});

		const response = await this.sendAndWaitForResponse(initMessage, 10000);
		
		if (!response || response.error) {
			throw new Error(`MCP init failed: ${response?.error?.message || 'No response'}`);
		}

		console.log('MCP initialize OK:', response);

		// Extract session ID if provided
		if (response.result?.sessionId) {
			this.sessionId = response.result.sessionId;
			console.log('Extracted session ID:', this.sessionId);
		}

		return response;
	}

	/**
	 * Send initialized notification to complete handshake
	 */
	async sendInitializedNotification() {
		try {
			const notification = this.jsonrpcNotification("notifications/initialized", {});
			await this.sendMessage(notification);
			console.log('Sent initialized notification');
			
			// Give server time to process
			await new Promise(resolve => setTimeout(resolve, 100));
		} catch (e) {
			console.log('initialized notification failed:', e.message);
		}
	}

	/**
	 * Complete initialization sequence (initialize + initialized notification)
	 */
	async initializeSession(clientInfo) {
		const initResponse = await this.initialize(clientInfo);
		await this.sendInitializedNotification();
		this.isConnected = true;
		return initResponse;
	}

	/**
	 * List available MCP capabilities (resources, prompts, tools, etc.)
	 */
	async listCapabilities() {
		const methods = [
			"resources/list",
			"ping", 
			"prompts/list",
			"tools/list",
			"logging/list",
			"completions/list"
		];
		
		const results = {};
		
		for (const method of methods) {
			try {
				console.log(`Trying ${method}...`);
				const request = this.jsonrpc(method, {});
				const response = await this.sendAndWaitForResponse(request);

				if (response && !response.error) {
					console.log(`MCP ${method}:`, response);
					results[method] = response;
				} else {
					console.log(`MCP ${method} failed:`, response?.error || 'No response');
					results[method] = { error: response?.error || 'No response' };
				}
			} catch (e) {
				console.log(`MCP ${method} error:`, e.message);
				results[method] = { error: e.message };
			}
		}
		
		return results;
	}

	/**
	 * Call a tool by name with given arguments
	 */
	async callTool(toolName, args = {}, progressToken = 0) {
		const request = this.jsonrpc("tools/call", {
			name: toolName,
			arguments: args,
			_meta: {
				progressToken
			}
		});
		
		return await this.sendAndWaitForResponse(request, 10000);
	}



	/**
	 * Abstract methods - must be implemented by subclasses
	 */
	async connect() {
		throw new Error('connect() must be implemented by subclass');
	}

	async sendMessage(_message) {
		throw new Error('sendMessage() must be implemented by subclass');
	}

	async sendAndWaitForResponse(_message, _timeoutMs) {
		throw new Error('sendAndWaitForResponse() must be implemented by subclass');
	}

	async close() {
		throw new Error('close() must be implemented by subclass');
	}

	async isServiceDetected() {
		throw new Error('isServiceDetected() must be implemented by subclass');
	}
}

/**
 * MCP client using Server-Sent Events (SSE) transport
 * Implements the MCP SSE transport as defined in the specification
 */
class McpSseClient extends McpClient {
	constructor(sseEndpoint = "/sse") {
		super(sseEndpoint, "2024-11-05");
		this.sessionEndpoint = null;
		this.eventSource = null;
		this.messageHandlers = new Map();
	}

	/**
	 * Connect to SSE endpoint and wait for session endpoint
	 */
	async connect() {
		console.log(`Connecting to SSE endpoint: ${this.server_endpoint}`);
		
		this.eventSource = new EventSource(this.server_endpoint);
		
		// Wait for the endpoint event
		return new Promise((resolve, reject) => {
			const timeout = setTimeout(() => {
				reject(new Error('Timeout waiting for endpoint'));
			}, 10000);

			this.eventSource.addEventListener('endpoint', (event) => {
				clearTimeout(timeout);
				this.sessionEndpoint = event.data;
				console.log(`Received session endpoint: ${this.sessionEndpoint}`);
				resolve();
			});

			this.eventSource.addEventListener('message', (event) => {
				try {
					const response = this.parseMcpResponse(event.data);
					if (response && response.id && this.messageHandlers.has(response.id)) {
						this.messageHandlers.get(response.id)(response);
					} else {
						console.log('Received server message:', response);
					}
				} catch (_e) {
					console.log('Received raw message:', event.data);
				}
			});

			this.eventSource.onerror = (error) => {
				console.log('SSE connection error:', error);
				console.log('\tEventSource readyState:', this.eventSource.readyState);
				console.log('\tEventSource URL:', this.eventSource.url);
				
				const stateNames = ['CONNECTING', 'OPEN', 'CLOSED'];
				console.log(`\tEventSource state: ${stateNames[this.eventSource.readyState] || 'UNKNOWN'}`);
				
				if (error.status) {
					console.log(`\tHTTP Status: ${error.status} ${error.message || ''}`);
				}
				
				if (this.eventSource.readyState === EventSource.CLOSED) {
					console.log('\tSSE connection has been closed');
				}
			};
		});
	}

	/**
	 * Send message via POST to session endpoint
	 */
	async sendMessage(message) {
		if (!this.sessionEndpoint) {
			throw new Error('No session endpoint available');
		}

		const response = await sooFetch(this.sessionEndpoint, {
			method: 'POST',
			credentials: 'omit',
			headers: {
				'content-type': 'application/json',
				'accept': 'application/json'
			},
			body: JSON.stringify(message)
		});

		return response;
	}

	/**
	 * Send message and wait for response via SSE
	 */
	async sendAndWaitForResponse(message, timeoutMs = 5000) {
		return new Promise((resolve, reject) => {
			const messageId = message.id;
			const timeoutId = setTimeout(() => {
				this.messageHandlers.delete(messageId);
				reject(new Error('Message response timeout'));
			}, timeoutMs);

			this.messageHandlers.set(messageId, (response) => {
				clearTimeout(timeoutId);
				this.messageHandlers.delete(messageId);
				resolve(response);
			});

			this.sendMessage(message).catch(reject);
		});
	}

	/**
	 * Close SSE connection
	 */
	async close() {
		if (this.eventSource) {
			this.eventSource.close();
			console.log('SSE connection closed');
		}
		this.isConnected = false;
	}

	/**
	 * Detect if service is MCP SSE
	 */
	async isServiceDetected() {
		try {
			return new Promise((resolve) => {
				let testEventSource = null;
				
				const timeout = setTimeout(() => {
					console.log('SSE detection timeout after 5s for', this.server_endpoint);
					if (testEventSource) {
						testEventSource.close();
					}
					resolve(false);
				}, 5000);  // Increased timeout to 5 seconds

				console.log('Testing SSE endpoint:', this.server_endpoint);
				testEventSource = new EventSource(this.server_endpoint);
				
				testEventSource.addEventListener('endpoint', (event) => {
					clearTimeout(timeout);
					console.log('SSE endpoint event received:', event.data);
					testEventSource.close();
					// Check if the endpoint data looks like a valid MCP endpoint
					const isValid = event.data && (event.data.includes('sessionId') || event.data.startsWith('/'));
					console.log('SSE endpoint valid?', isValid);
					resolve(isValid);
				});

				testEventSource.addEventListener('open', () => {
					console.log('SSE connection opened for', this.server_endpoint);
				});

				testEventSource.onerror = (error) => {
					clearTimeout(timeout);
					console.log('SSE connection error for', this.server_endpoint, error);
					console.log('EventSource readyState:', testEventSource.readyState);
					if (testEventSource) {
						testEventSource.close();
					}
					resolve(false);
				};
			});
		} catch (e) {
			console.error('SSE detection exception:', e);
			return false;
		}
	}
}

/**
 * MCP client using Streamable HTTP transport
 * Uses HTTP POST requests with optional SSE streaming in responses
 */
class McpStreamableHttpClient extends McpClient {
	constructor(endpoint = "/mcp") {
		super(endpoint, "2025-03-26");
	}

	/**
	 * Connect (no-op for HTTP, connection is per-request)
	 */
	async connect() {
		// HTTP doesn't need persistent connection
		console.log(`Using HTTP endpoint: ${this.server_endpoint}`);
	}

	/**
	 * Send message via HTTP POST
	 */
	async sendMessage(message) {
		const headers = {
			'content-type': 'application/json',
			'accept': 'application/json, text/event-stream'
		};

		if (this.sessionId) {
			headers['mcp-session-id'] = this.sessionId;
		}

		console.log('McpStreamableHttpClient sending to:', this.server_endpoint);
		console.log('Message:', message);
		console.log('typeof sooFetch:', typeof sooFetch);

		try {
			const response = await sooFetch(this.server_endpoint, {
				method: 'POST',
				credentials: 'omit',
				headers,
				body: JSON.stringify(message)
			});

			console.log('sooFetch response:', response);
			return response;
		} catch (error) {
			console.error('sooFetch error:', error);
			console.error('Error details:', {
				message: error.message,
				name: error.name,
				stack: error.stack
			});
			throw error;
		}
	}

	/**
	 * Read streaming response fully (for text/event-stream)
	 */
	async readStreamResponse(response) {
		const reader = response.body.getReader();
		const decoder = new TextDecoder();
		let fullText = '';
		
		try {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				fullText += decoder.decode(value, { stream: true });
				
				// Check if we have a complete JSON-RPC message
				// SSE format ends with double newline
				if (fullText.includes('\n\n') || fullText.includes('data: ')) {
					// Try to parse what we have
					const parsed = this.parseMcpResponse(fullText);
					if (parsed && parsed.jsonrpc) {
						// Got a complete message
						break;
					}
				}
			}
		} finally {
			reader.releaseLock();
		}
		
		return fullText;
	}

	/**
	 * Send message and wait for response (HTTP request/response)
	 */
	async sendAndWaitForResponse(message, _timeoutMs = 5000) {
		const response = await this.sendMessage(message);
		const contentType = response.headers.get('content-type');
		
		console.log('Response content-type:', contentType);
		console.log('Response status:', response.status);
		
		// Extract session ID from headers on first request
		if (!this.sessionId) {
			const sessionIdHeader = response.headers.get('mcp-session-id');
			if (sessionIdHeader) {
				this.sessionId = sessionIdHeader;
				console.log('Extracted MCP session ID from headers:', this.sessionId);
			}
		}
		
		let responseText;
		
		// Handle streaming responses (text/event-stream)
		if (contentType && contentType.includes('text/event-stream')) {
			console.log('Detected SSE streaming response - reading stream...');
			responseText = await this.readStreamResponse(response);
		} else {
			responseText = await response.text();
		}
		
		console.log('Response text (first 200 chars):', responseText.substring(0, 200));
		
		return this.parseMcpResponse(responseText);
	}

	/**
	 * Close (no-op for HTTP)
	 */
	async close() {
		// HTTP doesn't need explicit connection close
		this.isConnected = false;
	}

	/**
	 * Detect if service is MCP via HTTP
	 */
	async isServiceDetected() {
		try {
			console.log('Detecting MCP HTTP service at:', this.server_endpoint);
			
			// Temporarily increase timeout for detection of slow servers
			const originalTimeout = 15000;  // 15 seconds for slow servers
			const initMessage = this.jsonrpc("initialize", {
				protocolVersion: this.protocolVersion,
				capabilities: {},
				clientInfo: { name: "singularity-probe", version: "1.0.0" }
			});
			
			const initResponse = await this.sendAndWaitForResponse(initMessage, originalTimeout);
			
			console.log('HTTP detection - initialize response:', initResponse);
			
			// If initialize succeeded, it's an MCP server
			return !!(initResponse && !initResponse.error);
		} catch (e) {
			console.log('HTTP detection failed:', e.message);
			return false;
		}
	}
}

