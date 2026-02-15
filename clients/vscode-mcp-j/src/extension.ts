import * as vscode from 'vscode';
import * as path from 'path';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';

let outputChannel: vscode.OutputChannel;

// Phase 34: Reference IDE Client Integration
export function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel("MCP-J Runtime");
    outputChannel.show(true);

    outputChannel.appendLine("MCP-J Secure Runtime Initializing...");

    const command = context.extensionMode === vscode.ExtensionMode.Development
        ? path.join(context.extensionPath, '../../target/debug/mcp-j-cli')
        : path.join(context.extensionPath, 'bin', 'mcp-j-cli');

    // Default to generic profile for testing
    // In production, this would select based on the detected agent type
    const manifestPath = path.join(context.extensionPath, '../../profiles/generic.json');

    // Spawn wrapper with stderr interception
    // Note: The SDK's StdioServerTransport abstracts the spawn, but for stderr interception
    // we might need to implement a custom Transport or rely on the fact that
    // mcp-j-cli already multiplexes structured logs to stderr.
    // However, node spawn stdio handling is needed.

    // For this reference implementation, we assume the SDK client connects to 
    // the process. But the SDK usually takes a command and args.

    /*
      const transport = new StdioServerTransport({
          command,
          args: ["--manifest", manifestPath, "/usr/bin/python3", "-m", "mcp_host"],
          env: { ...process.env, RUST_LOG: "info" }
      });
      
      // stderr monitoring
      // The transport object exposes the process?
      // transport.process?.stderr?.on('data', (data) => { ... })
    */

    // To properly intercept stderr, we might extend StdioServerTransport or manual spawn.
    // For now, we will demonstrate the integration logic.

    outputChannel.appendLine(`Target Binary: ${command}`);
    outputChannel.appendLine(`Target Manifest: ${manifestPath}`);

    // Phase 43: Client IPC Telemetry Bridge
    // Manually spawn and bridge to SDK transport
    const cp = require('child_process');
    const child = cp.spawn(command, [
        '--manifest', manifestPath,
        '/usr/bin/python3' // Default entrypoint
    ], {
        env: { ...process.env, RUST_LOG: "info" }
    });

    child.stderr.on('data', (data: Buffer) => {
        const lines = data.toString().split('\n');
        for (const line of lines) {
            if (!line.trim()) continue;
            try {
                const log = JSON.parse(line);
                // Pretty print structured log to output channel
                const level = log.level || "INFO";
                const source = log.fields?.source || log.target || "unknown";
                const msg = log.fields?.message || log.message || "";

                outputChannel.appendLine(`[${level}] [${source}] ${msg}`);

                if (log.fields?.dst_ip) {
                    outputChannel.appendLine(`    > Forbidden Egress: ${log.fields.dst_ip}`);
                }
            } catch (e) {
                // Fallback for non-JSON stderr
                outputChannel.appendLine(`[RAW] ${line}`);
            }
        }
    });

    child.on('error', (err: any) => {
        outputChannel.appendLine(`[FATAL] Process Error: ${err.message}`);
    });

    child.on('close', (code: number) => {
        outputChannel.appendLine(`[EXIT] Process exited with code ${code}`);
    });

    // TODO: Connect child.stdin/stdout to MCP Client Transport
    // const transport = new StdioClientTransport(child.stdin, child.stdout);
}

export function deactivate() { }
