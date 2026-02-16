
import * as vscode from 'vscode';
import * as path from 'path';
import * as cp from 'child_process';
import { SecurityPanelProvider } from './securityPanel';

let outputChannel: vscode.OutputChannel;
let securityProvider: SecurityPanelProvider;
let childProcess: cp.ChildProcess | undefined;

export function activate(context: vscode.ExtensionContext) {
    // Phase 50: Integrated Security Terminal
    securityProvider = new SecurityPanelProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(SecurityPanelProvider.viewType, securityProvider)
    );

    outputChannel = vscode.window.createOutputChannel("MCP-J Runtime");
    outputChannel.show(true);
    outputChannel.appendLine("MCP-J Secure Runtime Initializing...");

    // Phase 49: Dynamic Sandbox Configuration
    const config = vscode.workspace.getConfiguration('mcp-j');

    // Resolve helper
    const resolvePath = (p: string) => {
        return p.replace(/\$\{extensionPath\}/g, context.extensionPath)
            .replace(/\$\{workspaceFolder\}/g, vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '');
    };

    const rawEnginePath = config.get<string>('enginePath') || '${extensionPath}/bin/mcp-j-cli';
    const rawProfilesPath = config.get<string>('profilesPath') || '${workspaceFolder}/.mcp-j/profiles';
    const defaultProfile = config.get<string>('defaultProfile') || 'generic.json';
    const logLevel = config.get<string>('logLevel') || 'info';
    const autoEphemeral = config.get<boolean>('autoEphemeral') ?? true;

    // Fallback logic for dev mode
    let enginePath = resolvePath(rawEnginePath);
    if (context.extensionMode === vscode.ExtensionMode.Development && !rawEnginePath.includes('target')) {
        // If in dev mode and using default path, try target/debug
        const devPath = path.join(context.extensionPath, '../../target/debug/mcp-j-cli');
        outputChannel.appendLine(`[DEV] Overriding engine path to: ${devPath}`);
        enginePath = devPath;
    }

    const profilesPath = resolvePath(rawProfilesPath);
    const manifestPath = path.join(profilesPath, defaultProfile);

    // Validate if manifest exists (soft check)
    // vscode.workspace.fs.stat(vscode.Uri.file(manifestPath)).then(...)

    outputChannel.appendLine(`Engine: ${enginePath}`);
    outputChannel.appendLine(`Profile: ${manifestPath}`);
    outputChannel.appendLine(`Log Level: ${logLevel.toUpperCase()}`);
    outputChannel.appendLine(`Ephemeral: ${autoEphemeral}`);

    // Spawn Process
    try {
        const env = {
            ...process.env,
            RUST_LOG: logLevel,
            MCP_J_EPHEMERAL: autoEphemeral ? "true" : "false"
        };

        // Use python3 as default entrypoint for demo/testing
        // In real usage, this might be dynamic based on the task
        const args = ['--manifest', manifestPath, '/usr/bin/python3'];

        outputChannel.appendLine(`Spawning: ${enginePath} ${args.join(' ')}`);

        childProcess = cp.spawn(enginePath, args, { env });

        if (childProcess.stderr) {
            childProcess.stderr.on('data', (data: Buffer) => {
                const lines = data.toString().split('\n');
                for (const line of lines) {
                    if (!line.trim()) continue;
                    handleLogLine(line);
                }
            });
        }

        if (childProcess.stdout) {
            // For now just pipe to output, later this is the JSON-RPC transport
            childProcess.stdout.on('data', (data: Buffer) => {
                // console.log("STDOUT:", data.toString());
            });
        }

        childProcess.on('error', (err: Error) => {
            outputChannel.appendLine(`[FATAL] Spawning failed: ${err.message}`);
            vscode.window.showErrorMessage(`MCP-J Engine failed to start: ${err.message}`);
        });

        childProcess.on('close', (code: number) => {
            outputChannel.appendLine(`[EXIT] Process exited with code ${code}`);
            securityProvider.addLog({
                timestamp: new Date().toISOString(),
                level: 'WARN',
                message: `Process exited with code ${code}`,
                target: 'supervisor'
            });
        });

    } catch (e: any) {
        outputChannel.appendLine(`[ERROR] Setup failed: ${e.message}`);
    }
}

function handleLogLine(line: string) {
    try {
        // Attempt to parse structured JSON log
        const log = JSON.parse(line);

        // 1. Send to Security Terminal (Phase 50)
        securityProvider.addLog(log);

        // 2. Alert on High-Risk Events (Phase 51)
        detectThreats(log);

        // 3. Fallback to Output Channel
        const level = log.level || "INFO";
        const msg = log.message || log.fields?.message || "";
        outputChannel.appendLine(`[${level}] ${msg}`);

    } catch (e) {
        // Not JSON - probably raw stderr panic or artifact
        outputChannel.appendLine(`[RAW] ${line}`);
        securityProvider.addLog({
            timestamp: new Date().toISOString(),
            level: 'RAW',
            message: line,
            target: 'stderr'
        });
    }
}

function detectThreats(log: any) {
    // Logic to detect security violations
    const isBlocked = log.message?.includes("Blocked") || log.fields?.message?.includes("Blocked");
    const isError = log.level === 'ERROR';

    if (isBlocked || isError) {
        const msg = log.message || log.fields?.message || "Security violation detected";
        vscode.window.showWarningMessage(`MCP-J Alert: ${msg}`, 'Open Security Log')
            .then(selection => {
                if (selection === 'Open Security Log') {
                    vscode.commands.executeCommand('mcp-j-security.focus');
                }
            });
    }
}

export function deactivate() {
    if (childProcess) {
        childProcess.kill();
    }
}
