
import * as vscode from 'vscode';
import * as path from 'path';
import * as cp from 'child_process';
import { SecurityPanelProvider } from './securityPanel';

let outputChannel: vscode.OutputChannel;
let securityProvider: SecurityPanelProvider;
let childProcess: cp.ChildProcess | undefined;
let pendingManifest: string | undefined;

export async function activate(context: vscode.ExtensionContext) {
    // Phase 66: IDE Transport Hijacking
    await hijackMcpConfiguration();

    // Phase 50: Integrated Security Terminal
    securityProvider = new SecurityPanelProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(SecurityPanelProvider.viewType, securityProvider)
    );

    outputChannel = vscode.window.createOutputChannel("MCP-J Runtime");
    outputChannel.show(true);
    outputChannel.appendLine("MCP-J Secure Runtime Initializing...");

    // Phase 57: Native Chat Participant Integration
    const handler: vscode.ChatRequestHandler = async (request, context, stream, token) => {
        if (request.command === 'audit') {
            await handleAuditCommand(stream, token);
        } else if (request.command === 'plan') {
            await handlePlanCommand(stream, token);
        } else if (request.command === 'configure') {
            stream.markdown("Redirecting to workspace analysis...");
            await handlePlanCommand(stream, token);
        } else {
            stream.markdown("I can help you audit MCP-J security events. Try `@mcp-j /audit` or `@mcp-j /plan`.");
        }
    };

    context.subscriptions.push(
        vscode.chat.createChatParticipant('mcp-j.securityBot', handler)
    );

    // Register Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('mcp-j.autoConfigure', async () => {
            await vscode.commands.executeCommand('workbench.action.chat.open', { query: '@mcp-j /plan' });
        }),
        vscode.commands.registerCommand('mcp-j.plan', async () => {
            await vscode.commands.executeCommand('workbench.action.chat.open', { query: '@mcp-j /plan' });
        }),
        vscode.commands.registerCommand('mcp-j.applyProfile', async () => {
            await applyPendingProfile(context);
        })
    );

    // Phase 49: Dynamic Sandbox Configuration
    const config = vscode.workspace.getConfiguration('mcp-j');

    const autoConfigureOnOpen = config.get<boolean>('autoConfigureOnOpen') ?? true;
    if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 && autoConfigureOnOpen) {
        const root = vscode.workspace.workspaceFolders[0].uri;
        const profileUri = vscode.Uri.joinPath(root, '.mcp-j', 'profiles', 'generic.json');
        try {
            await vscode.workspace.fs.stat(profileUri);
            startEngine(context);
        } catch (e) {
            vscode.window.showInformationMessage(
                "MCP-J is not configured for this workspace. Analyze workspace to generate a security profile?",
                "Analyze Workspace",
                "Dismiss"
            ).then(selection => {
                if (selection === 'Analyze Workspace') {
                    vscode.commands.executeCommand('mcp-j.plan');
                }
            });
        }
    } else {
        if (vscode.workspace.workspaceFolders) {
            const root = vscode.workspace.workspaceFolders[0].uri;
            const profileUri = vscode.Uri.joinPath(root, '.mcp-j', 'profiles', 'generic.json');
            try {
                await vscode.workspace.fs.stat(profileUri);
                startEngine(context);
            } catch (e) { }
        }
    }
}

async function handleAuditCommand(stream: vscode.ChatResponseStream, token: vscode.CancellationToken) {
    stream.progress('Analyzing ring buffer telemetry...');
    const lastTrap = securityProvider.getLastTelemetryEvent();

    if (!lastTrap) {
        stream.markdown("No security events found in the current session.");
        return;
    }

    const prompt = `Explain this kernel trap to the developer and suggest a manifest fix: ${JSON.stringify(lastTrap)}`;
    const messages = [vscode.LanguageModelChatMessage.User(prompt)];

    try {
        const [model] = await vscode.lm.selectChatModels({ family: 'gpt-4o' });
        if (model) {
            const chatResponse = await model.sendRequest(messages, {}, token);
            for await (const fragment of chatResponse.text) {
                stream.markdown(fragment);
            }
        } else {
            stream.markdown("No compatible LLM found to analyze the trap.");
        }
    } catch (err: any) {
        stream.markdown(`Analysis failed: ${err.message}`);
    }
}

async function handlePlanCommand(stream: vscode.ChatResponseStream, token: vscode.CancellationToken) {
    if (!vscode.workspace.workspaceFolders) {
        stream.markdown("No workspace open.");
        return;
    }

    const root = vscode.workspace.workspaceFolders[0].uri;

    stream.progress('Scanning workspace structure...');
    const files = await vscode.workspace.fs.readDirectory(root);
    const fileList = files.map(([name, type]) => name);

    const [model] = await vscode.lm.selectChatModels({ family: 'gpt-4o' });
    if (!model) {
        stream.markdown("No compatible 'gpt-4o' model found.");
        return;
    }

    const prompt = `
        You are a Senior Systems Security Engineer configuring the MCP-J Secure Runtime.
        The user has a workspace with these files: ${JSON.stringify(fileList)}.
        
        Task:
        1. Analyze the project structure to detect the language and framework.
        2. Generate a 'SandboxManifest' JSON file validation against manifest.schema.json.
        3. Enforce strict least-privilege: include '${root.fsPath}' in 'allowed_paths' and minimal network egress.
        
        Output:
        - A brief explanation of the detected stack and security choices.
        - The raw JSON content wrapped in a markdown code block (json).
        - No other text outside the explanation.
    `;

    const messages = [vscode.LanguageModelChatMessage.User(prompt)];

    stream.progress('Generating Zero-Trust Sandbox Blueprint...');

    try {
        const response = await model.sendRequest(messages, {}, token);

        let fullText = "";
        for await (const fragment of response.text) {
            fullText += fragment;
            stream.markdown(fragment);
        }

        const jsonMatch = fullText.match(/```json\s*([\s\S]*?)\s*```/) || fullText.match(/```\s*([\s\S]*?)\s*```/);

        if (jsonMatch) {
            pendingManifest = jsonMatch[1];
            stream.markdown("\n\n---\n");
            stream.markdown("Review the blueprint above. Click below to apply this configuration to the workspace.\n\n");
            stream.button({
                command: 'mcp-j.applyProfile',
                title: 'Apply Profile'
            });
        } else {
            stream.markdown("\n\n**Error:** Could not extract valid JSON from the response.");
        }

    } catch (err: any) {
        stream.markdown(`AI Request Failed: ${err.message}`);
    }
}

async function applyPendingProfile(context: vscode.ExtensionContext) {
    if (!pendingManifest) {
        vscode.window.showErrorMessage("No security profile is pending. Run '@mcp-j /plan' first.");
        return;
    }

    if (!vscode.workspace.workspaceFolders) { return; }
    const root = vscode.workspace.workspaceFolders[0].uri;

    try {
        JSON.parse(pendingManifest);

        const profileDir = vscode.Uri.joinPath(root, '.mcp-j', 'profiles');
        const profileUri = vscode.Uri.joinPath(profileDir, 'generic.json');

        await vscode.workspace.fs.createDirectory(profileDir);
        await vscode.workspace.fs.writeFile(profileUri, Buffer.from(pendingManifest));

        vscode.window.showInformationMessage(`Security profile applied to ${profileUri.fsPath}`);

        startEngine(context);
        pendingManifest = undefined;

    } catch (e: any) {
        vscode.window.showErrorMessage(`Failed to apply profile: ${e.message}`);
    }
}

// Refactored Engine Start Logic
function startEngine(context: vscode.ExtensionContext) {
    terminateExistingEngine();

    const config = getExtensionConfig(context);
    const paths = resolvePaths(context, config);

    outputChannel.appendLine(`Engine: ${paths.enginePath}`);
    outputChannel.appendLine(`Profile: ${paths.manifestPath}`);
    outputChannel.appendLine(`Log Level: ${config.logLevel.toUpperCase()}`);

    try {
        childProcess = spawnEngineProcess(paths, config);
        attachProcessListeners(childProcess);
    } catch (e: any) {
        outputChannel.appendLine(`[ERROR] Setup failed: ${e.message}`);
    }
}

function terminateExistingEngine() {
    if (childProcess) {
        outputChannel.appendLine("Restarting MCP-J Engine...");
        childProcess.kill();
        childProcess = undefined;
    }
}

interface EngineConfig {
    rawEnginePath: string;
    rawProfilesPath: string;
    defaultProfile: string;
    logLevel: string;
    autoEphemeral: boolean;
}

function getExtensionConfig(context: vscode.ExtensionContext): EngineConfig {
    const config = vscode.workspace.getConfiguration('mcp-j');
    return {
        rawEnginePath: config.get<string>('enginePath') || '${extensionPath}/bin/mcp-j-cli',
        rawProfilesPath: config.get<string>('profilesPath') || '${workspaceFolder}/.mcp-j/profiles',
        defaultProfile: config.get<string>('defaultProfile') || 'generic.json',
        logLevel: config.get<string>('logLevel') || 'info',
        autoEphemeral: config.get<boolean>('autoEphemeral') ?? true
    };
}

interface ResolvedPaths {
    enginePath: string;
    manifestPath: string;
}

function resolvePaths(context: vscode.ExtensionContext, config: EngineConfig): ResolvedPaths {
    const resolve = (p: string) => {
        return p.replace(/\$\{extensionPath\}/g, context.extensionPath)
            .replace(/\$\{workspaceFolder\}/g, vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '');
    };

    let enginePath = resolve(config.rawEnginePath);
    // Fallback logic for dev mode
    if (context.extensionMode === vscode.ExtensionMode.Development && !config.rawEnginePath.includes('target')) {
        const devPath = path.join(context.extensionPath, '../../target/debug/mcp-j-cli');
        enginePath = devPath;
    }

    const profilesPath = resolve(config.rawProfilesPath);
    const manifestPath = path.join(profilesPath, config.defaultProfile);

    return { enginePath, manifestPath };
}

function spawnEngineProcess(paths: ResolvedPaths, config: EngineConfig): cp.ChildProcess {
    const env = {
        ...process.env,
        RUST_LOG: config.logLevel,
        MCP_J_EPHEMERAL: config.autoEphemeral ? "true" : "false"
    };
    const args = ['--manifest', paths.manifestPath, '/usr/bin/python3'];

    outputChannel.appendLine(`Spawning: ${paths.enginePath} ${args.join(' ')}`);
    return cp.spawn(paths.enginePath, args, { env });
}

function attachProcessListeners(child: cp.ChildProcess) {
    if (child.stderr) {
        child.stderr.on('data', (data: Buffer) => {
            const lines = data.toString().split('\n');
            for (const line of lines) {
                if (!line.trim()) continue;
                handleLogLine(line);
            }
        });
    }

    child.on('error', (err: Error) => {
        outputChannel.appendLine(`[FATAL] Spawning failed: ${err.message}`);
        vscode.window.showErrorMessage(`MCP-J Engine failed to start: ${err.message}`);
    });

    child.on('close', (code: number) => {
        outputChannel.appendLine(`[EXIT] Process exited with code ${code}`);
        securityProvider.addLog({
            timestamp: new Date().toISOString(),
            level: 'WARN',
            message: `Process exited with code ${code}`,
            target: 'supervisor'
        });
    });
}

function handleLogLine(line: string) {
    try {
        const log = JSON.parse(line);
        securityProvider.addLog(log);
        detectThreats(log);

        const level = log.level || "INFO";
        const msg = log.message || log.fields?.message || "";
        outputChannel.appendLine(`[${level}] ${msg}`);

    } catch (e) {
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

async function hijackMcpConfiguration() {
    // Workspace Config
    if (vscode.workspace.workspaceFolders) {
        const root = vscode.workspace.workspaceFolders[0].uri;
        const mcpConfigUri = vscode.Uri.joinPath(root, '.vscode', 'mcp.json');
        await processConfigFile(mcpConfigUri);
    }

    // Global Config (User Settings)
    // Note: VS Code API abstracting global settings is tricky for raw JSON edits.
    // We typically recommend users use workspace config. 
    // But we can check for a global mcp.json in standard locations if we knew them.
    // Since standard MCP doesn't defined a fixed global path cross-platform effortlessly in this context,
    // we will stick to workspace for now as per "safe" extension guidelines, 
    // OR we can check if the user provided a global path in our extension settings.

    // HOWEVER, the user asked to search "user's global settings.json".
    // This implies VSCode's settings.json.
    // We can inspect `vscode.workspace.getConfiguration('mcp')`?
    // Actually, the "mcp-servers" might be defined there.

    const mcpConfig = vscode.workspace.getConfiguration('mcp');
    const servers = mcpConfig.get<any>('mcpServers');
    if (servers) {
        let modified = false;
        const newServers = JSON.parse(JSON.stringify(servers)); // Deep copy

        for (const serverName in newServers) {
            const server = newServers[serverName];
            if (server.command && !server.command.includes('mcp-j-cli')) {
                const originalCmd = server.command;
                const originalArgs = server.args || [];

                server.command = "mcp-j-cli";
                // We need an absolute path to profile? Or generic.
                // For global, we might default to a bundled profile or ask user.
                // Let's use a safe default generic profile relative to... where?
                // We'll use the one in the workspace if available, or skip for now if no workspace.
                if (vscode.workspace.workspaceFolders) {
                    server.args = [
                        "--manifest",
                        ".mcp-j/profiles/generic.json",
                        originalCmd,
                        ...originalArgs
                    ];
                    modified = true;
                    outputChannel.appendLine(`[Hijack] Rewrote Global MCP server '${serverName}' to use mcp-j-cli.`);
                }
            }
        }

        if (modified) {
            await mcpConfig.update('mcpServers', newServers, vscode.ConfigurationTarget.Global);
            vscode.window.showInformationMessage("MCP-J: Hijacked and hardened Global MCP server configurations.");
        }
    }
}

async function processConfigFile(uri: vscode.Uri) {
    try {
        const doc = await vscode.workspace.fs.readFile(uri);
        const config = JSON.parse(doc.toString());
        let modified = false;

        if (config.mcpServers) {
            for (const serverName in config.mcpServers) {
                const server = config.mcpServers[serverName];
                if (server.command && !server.command.includes('mcp-j-cli')) {
                    const originalCmd = server.command;
                    const originalArgs = server.args || [];

                    server.command = "mcp-j-cli";
                    server.args = [
                        "--manifest",
                        ".mcp-j/profiles/generic.json",
                        originalCmd,
                        ...originalArgs
                    ];

                    modified = true;
                    outputChannel.appendLine(`[Hijack] Rewrote MCP server '${serverName}' to use mcp-j-cli.`);
                }
            }
        }

        if (modified) {
            await vscode.workspace.fs.writeFile(uri, Buffer.from(JSON.stringify(config, null, 4)));
            vscode.window.showInformationMessage("MCP-J: Hijacked and hardened MCP server configurations.");
        }
    } catch (e) {
    }
}

export function deactivate() {
    if (childProcess) {
        childProcess.kill();
    }
}
