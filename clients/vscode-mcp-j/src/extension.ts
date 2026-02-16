
import * as vscode from 'vscode';
import * as path from 'path';
import * as cp from 'child_process';
import { SecurityPanelProvider } from './securityPanel';

let outputChannel: vscode.OutputChannel;
let securityProvider: SecurityPanelProvider;
let childProcess: cp.ChildProcess | undefined;
let pendingManifest: string | undefined;

export async function activate(context: vscode.ExtensionContext) {
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
            // Legacy alias, redirect to plan
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
            // Programmatically open chat with the query
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

    // Startup Check: Zero-Friction Onboarding
    const autoConfigureOnOpen = config.get<boolean>('autoConfigureOnOpen') ?? true;
    if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 && autoConfigureOnOpen) {
        const root = vscode.workspace.workspaceFolders[0].uri;
        const profileUri = vscode.Uri.joinPath(root, '.mcp-j', 'profiles', 'generic.json');
        try {
            await vscode.workspace.fs.stat(profileUri);
            // Profile exists, start engine
            startEngine(context);
        } catch (e) {
            // Profile does not exist
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
        // Even if no profile check, if we have configuration, try to start
        // We only don't start if we are waiting for a profile
        // Check if profile exists; if so, start.
        if (vscode.workspace.workspaceFolders) {
            const root = vscode.workspace.workspaceFolders[0].uri;
            const profileUri = vscode.Uri.joinPath(root, '.mcp-j', 'profiles', 'generic.json');
            try {
                await vscode.workspace.fs.stat(profileUri);
                startEngine(context);
            } catch (e) {
                // Do nothing, wait for user
            }
        }
    }
}

async function handleAuditCommand(stream: vscode.ChatResponseStream, token: vscode.CancellationToken) {
    stream.progress('Analyzing ring buffer telemetry...');
    // Extract the last blocked event from the Ring Buffer
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

    // 1. Scan Workspace
    stream.progress('Scanning workspace structure...');
    const files = await vscode.workspace.fs.readDirectory(root);
    const fileList = files.map(([name, type]) => name);

    // 2. Select Model
    const [model] = await vscode.lm.selectChatModels({ family: 'gpt-4o' });
    if (!model) {
        stream.markdown("No compatible 'gpt-4o' model found.");
        return;
    }

    // 3. Send Prompt
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

        // Logic to extract JSON
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
        // Validate JSON
        JSON.parse(pendingManifest);

        const profileDir = vscode.Uri.joinPath(root, '.mcp-j', 'profiles');
        const profileUri = vscode.Uri.joinPath(profileDir, 'generic.json');

        await vscode.workspace.fs.createDirectory(profileDir);
        await vscode.workspace.fs.writeFile(profileUri, Buffer.from(pendingManifest));

        vscode.window.showInformationMessage(`Security profile applied to ${profileUri.fsPath}`);

        // Start engine now that profile exists
        startEngine(context);

        // Clear pending
        pendingManifest = undefined;

    } catch (e: any) {
        vscode.window.showErrorMessage(`Failed to apply profile: ${e.message}`);
    }
}

// Refactored Engine Start Logic
function startEngine(context: vscode.ExtensionContext) {
    // If running, kill it first
    if (childProcess) {
        outputChannel.appendLine("Restarting MCP-J Engine...");
        childProcess.kill();
        childProcess = undefined;
    }

    const config = vscode.workspace.getConfiguration('mcp-j');

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
        const devPath = path.join(context.extensionPath, '../../target/debug/mcp-j-cli');
        enginePath = devPath;
    }

    const profilesPath = resolvePath(rawProfilesPath);
    const manifestPath = path.join(profilesPath, defaultProfile);

    outputChannel.appendLine(`Engine: ${enginePath}`);
    outputChannel.appendLine(`Profile: ${manifestPath}`);
    outputChannel.appendLine(`Log Level: ${logLevel.toUpperCase()}`);

    try {
        const env = {
            ...process.env,
            RUST_LOG: logLevel,
            MCP_J_EPHEMERAL: autoEphemeral ? "true" : "false"
        };
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

export function deactivate() {
    if (childProcess) {
        childProcess.kill();
    }
}
