
import * as vscode from 'vscode';

export class SecurityPanelProvider implements vscode.WebviewViewProvider {

    public static readonly viewType = 'mcp-j-security';

    private _view?: vscode.WebviewView;

    constructor(
        private readonly _extensionUri: vscode.Uri,
    ) { }

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken,
    ) {
        this._view = webviewView;

        webviewView.webview.options = {
            // Allow scripts in the webview
            enableScripts: true,
            localResourceRoots: [
                this._extensionUri
            ]
        };

        webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);
    }

    private _logBuffer: any[] = [];
    private readonly MAX_BUFFER_SIZE = 50;

    public addLog(entry: any) {
        // Maintain local ring buffer for query answering
        this._logBuffer.push(entry);
        if (this._logBuffer.length > this.MAX_BUFFER_SIZE) {
            this._logBuffer.shift();
        }

        if (this._view) {
            this._view.webview.postMessage({ type: 'log', entry: entry });
        }
    }

    public getLastTelemetryEvent(): any | undefined {
        // Return latest interesting event (preferably an error or block)
        // If none, return the absolute last log
        const reversed = [...this._logBuffer].reverse();
        const block = reversed.find(e => {
            const msg = e.message || e.fields?.message || "";
            return msg.includes("Blocked") || e.level === 'ERROR';
        });
        return block || reversed[0];
    }

    public clear() {
        this._logBuffer = [];
        if (this._view) {
            this._view.webview.postMessage({ type: 'clear' });
        }
    }

    private _getHtmlForWebview(webview: vscode.Webview) {
        const nonce = getNonce();

        return `<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>MCP-J Security Terminal</title>
                <style nonce="${nonce}">
                    body {
                        font-family: var(--vscode-editor-font-family);
                        font-size: var(--vscode-editor-font-size);
                        background-color: var(--vscode-editor-background);
                        color: var(--vscode-editor-foreground);
                        margin: 0;
                        padding: 10px;
                        overflow-x: hidden;
                    }
                    .log-entry {
                        margin-bottom: 4px;
                        padding: 4px;
                        border-left: 3px solid transparent;
                        font-family: 'Courier New', Courier, monospace;
                        white-space: pre-wrap;
                        word-break: break-all;
                    }
                    .log-entry.info { border-left-color: var(--vscode-debugIcon-startForeground); }
                    .log-entry.warn { border-left-color: var(--vscode-debugIcon-pauseForeground); background-color: rgba(255, 255, 0, 0.05); }
                    .log-entry.error { border-left-color: var(--vscode-debugIcon-stopForeground); background-color: rgba(255, 0, 0, 0.05); }
                    
                    .timestamp { color: var(--vscode-descriptionForeground); margin-right: 8px; }
                    .target { color: var(--vscode-symbolIcon-classForeground); font-weight: bold; margin-right: 8px; }
                    .message { }
                    .fields { display: block; margin-left: 20px; color: var(--vscode-textPreformat-foreground); font-size: 0.9em; }
                    
                    /* Custom Highlights */
                    .highlight-egress { color: #f48771; } /* Reddish */
                    .highlight-fs { color: #cca700; } /* Yellowish */
                    .highlight-rpc { color: #89d185; } /* Greenish */

                </style>
			</head>
			<body>
				<div id="log-container"></div>
				<script nonce="${nonce}">
                    const vscode = acquireVsCodeApi();
                    const container = document.getElementById('log-container');
                    const MAX_LOG_LINES = 1000;

                    window.addEventListener('message', event => {
                        const message = event.data;
                        switch (message.type) {
                            case 'log':
                                addLogEntry(message.entry);
                                break;
                            case 'clear':
                                container.innerHTML = '';
                                break;
                        }
                    });
                    
                    function escapeHtml(unsafe) {
                        return unsafe
                             .replace(/&/g, "&amp;")
                             .replace(/</g, "&lt;")
                             .replace(/>/g, "&gt;")
                             .replace(/"/g, "&quot;")
                             .replace(/'/g, "&#039;");
                    }

                    function addLogEntry(entry) {
                        const div = document.createElement('div');
                        div.className = 'log-entry';
                        
                        // Determine level class
                        const level = (entry.level || 'INFO').toLowerCase();
                        div.classList.add(level);

                        // Timestamp
                        const tsSpan = document.createElement('span');
                        tsSpan.className = 'timestamp';
                        tsSpan.textContent = new Date(entry.timestamp || Date.now()).toLocaleTimeString();
                        div.appendChild(tsSpan);

                        // Target/Source
                        const targetSpan = document.createElement('span');
                        targetSpan.className = 'target';
                        // Safe textContent usage
                        targetSpan.textContent = \`[\${entry.target || entry.source || 'unknown'}]\`;
                        div.appendChild(targetSpan);

                        // Message with heuristic highlighting (TextContent is safe)
                        const msgSpan = document.createElement('span');
                        msgSpan.className = 'message';
                        const rawMsg = entry.message || entry.fields?.message || '';
                        msgSpan.textContent = rawMsg;
                        
                        if (rawMsg.includes('Blocked') || entry.fields?.error) {
                            div.classList.add('error');
                            msgSpan.classList.add('highlight-egress');
                        }
                        
                        div.appendChild(msgSpan);

                        // Extra Fields
                        let fieldsObj = null;
                        if (entry.fields) {
                            const { message, ...rest } = entry.fields;
                            if (Object.keys(rest).length > 0) fieldsObj = rest;
                        } else if (entry.pid || entry.dst_ip) {
                            const { timestamp, level, message, target, ...rest } = entry;
                            fieldsObj = rest;
                        }

                        if (fieldsObj) {
                            const fieldsDiv = document.createElement('div');
                            fieldsDiv.className = 'fields';
                            // Utilize JSON.stringify which is safe for textContent
                            fieldsDiv.textContent = JSON.stringify(fieldsObj, null, 2);
                            div.appendChild(fieldsDiv);
                        }

                        container.appendChild(div);
                        
                        // Ring Buffer Logic (Phase 50.2)
                        while (container.childNodes.length > MAX_LOG_LINES) {
                            container.removeChild(container.firstChild);
                        }

                        window.scrollTo(0, document.body.scrollHeight);
                    }
                </script>
			</body>
			</html>`;
    }
}

function getNonce() {
    let text = '';
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < 32; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
}
