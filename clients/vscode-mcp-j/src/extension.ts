
import * as vscode from 'vscode';
import * as path from 'path';
import * as cp from 'child_process';
import { SecurityPanelProvider } from './securityPanel';

let outputChannel: vscode.OutputChannel;
let securityProvider: SecurityPanelProvider;
let childProcess: cp.ChildProcess | undefined;

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
                // Pass to the active Antigravity/Copilot model
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
        } else if (request.command === 'configure') {
            await performAutoConfiguration(stream, token);
        } else {
            stream.markdown("I can help you audit MCP-J security events. Try `@mcp-j /audit` or `@mcp-j /configure`.");
        }
    };

    context.subscriptions.push(
        vscode.chat.createChatParticipant('mcp-j.securityBot', handler)
    );

    // Register Auto-Configure Command
    context.subscriptions.push(
        vscode.commands.registerCommand('mcp-j.autoConfigure', async () => {
            // When run as a command, strictly use notifications/output, but we can reuse logic
            // We pass undefined for stream to indicate non-chat context
            await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: "MCP-J: Generating Sandbox Profile...",
                cancellable: true
            }, async (progress, token) => {
                await performAutoConfiguration(undefined, token);
            });
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
        } catch (e) {
            // Profile does not exist
            vscode.window.showInformationMessage(
                "MCP-J is not configured for this workspace. Generate an isolated sandbox profile using the active AI model?",
                "Auto-Configure",
                "Dismiss"
            ).then(selection => {
                if (selection === 'Auto-Configure') {
                    vscode.commands.executeCommand('mcp-j.autoConfigure');
                }
            });
        }
    }

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

async function performAutoConfiguration(stream?: vscode.ChatResponseStream, token?: vscode.CancellationToken) {
    if (!vscode.workspace.workspaceFolders) {
        if (stream) { stream.markdown("No workspace open."); }
        else { vscode.window.showErrorMessage("No workspace open."); }
        return;
    }

    const root = vscode.workspace.workspaceFolders[0].uri;

    // 1. Scan Workspace
    if (stream) stream.progress('Scanning workspace structure...');
    else outputChannel.appendLine("Scanning workspace structure...");

    // Basic heuristic: list top-level files
    const files = await vscode.workspace.fs.readDirectory(root);
    const fileList = files.map(([name, type]) => name);

    // 2. Select Model
    const [model] = await vscode.lm.selectChatModels({ family: 'gpt-4o' });
    if (!model) {
        const err = "No compatible 'gpt-4o' model found.";
        if (stream) stream.markdown(err);
        else vscode.window.showErrorMessage(err);
        return;
    }

    // 3. Send Prompt
    const prompt = `
        You are a security engineer configuring the MCP-J Secure Runtime.
        The user has a workspace with these files: ${JSON.stringify(fileList)}.
        
        Generate a 'SandboxManifest' JSON file (validating against manifest.schema.json) that:
        1. Enforces strict least-privilege for this specific project type (Node, Rust, Python, etc).
        2. Includes '${root.fsPath}' in 'allowed_paths'.
        3. Only allows necessary network access (e.g. if it looks like a web app).
        
        Return ONLY the raw JSON content within a markdown code block. No conversational text.
    `;

    const messages = [vscode.LanguageModelChatMessage.User(prompt)];

    if (stream) stream.progress('Consulting AI model for least-privilege profile...');
    else outputChannel.appendLine("Consulting AI model...");

    try {
        const response = await model.sendRequest(messages, {}, token || new vscode.CancellationTokenSource().token);

        let fullText = "";
        for await (const fragment of response.text) {
            fullText += fragment;
            if (stream) stream.markdown(fragment); // specific output logic?
            // If streaming to chat, we probably shouldn't stream the raw JSON as the *only* thing 
            // if we want to show a success message later.
            // But requirement says "Output the generation plan and result".
        }

        // Logic to extract JSON and write it
        const jsonMatch = fullText.match(/```json\s*([\s\S]*?)\s*```/) || fullText.match(/```\s*([\s\S]*?)\s*```/);
        const jsonContent = jsonMatch ? jsonMatch[1] : fullText;

        try {
            // Verify it parses
            JSON.parse(jsonContent);

            const profileDir = vscode.Uri.joinPath(root, '.mcp-j', 'profiles');
            const profileUri = vscode.Uri.joinPath(profileDir, 'generic.json');

            // Ensure dir exists
            await vscode.workspace.fs.createDirectory(profileDir);
            await vscode.workspace.fs.writeFile(profileUri, Buffer.from(jsonContent));

            const successMsg = `\n\n**Success!** generic.json generated at ${profileUri.fsPath}`;
            if (stream) stream.markdown(successMsg);
            else {
                outputChannel.appendLine(successMsg);
                vscode.window.showInformationMessage("MCP-J Profile successfully generated!");
            }

        } catch (parseErr) {
            const msg = `Failed to parse generated JSON: ${parseErr}`;
            if (stream) stream.markdown(`\n\n**Error**: ${msg}`);
            else vscode.window.showErrorMessage(msg);
        }

    } catch (err: any) {
        const msg = `AI Request Failed: ${err.message}`;
        if (stream) stream.markdown(msg);
        else vscode.window.showErrorMessage(msg);
    }
}
