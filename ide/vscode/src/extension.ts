import * as vscode from "vscode";
import { execFile } from "child_process";
import * as path from "path";

/** Shape of a finding emitted by `codequal ... --format json`. */
interface Finding {
  file: string;
  line: number;
  end_line: number;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  description: string;
  suggestion: string;
  confidence: number;
  rule_id: string;
  source: string;
}

interface ScanPayload {
  mode: string;
  model: string;
  files_scanned: number;
  total_findings: number;
  findings: Finding[];
}

let diagnostics: vscode.DiagnosticCollection;
let status: vscode.StatusBarItem;
let output: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection("codequal");
  output = vscode.window.createOutputChannel("CodeQual");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  status.text = "$(shield) CodeQual";
  status.command = "codequal.scanFile";
  status.tooltip = "Scan the current file with CodeQual";
  status.show();

  context.subscriptions.push(
    diagnostics,
    output,
    status,
    vscode.commands.registerCommand("codequal.scanFile", scanActiveFile),
    vscode.commands.registerCommand("codequal.scanWorkspace", scanWorkspace),
    vscode.commands.registerCommand("codequal.clear", () => diagnostics.clear()),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (config().get<boolean>("scanOnSave", true)) {
        void scanDocument(doc);
      }
    })
  );
}

export function deactivate(): void {
  diagnostics?.dispose();
}

function config(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration("codequal");
}

/** Build the shared engine/output flags from settings. */
function commonArgs(): string[] {
  const cfg = config();
  const args = ["--format", "json", "--fail-on", "none", "--quiet"];
  if (!cfg.get<boolean>("useAI", true)) {
    args.push("--no-ai");
  }
  const model = cfg.get<string>("model", "");
  if (model) {
    args.push("--model", model);
  }
  const minConfidence = cfg.get<number>("minConfidence", 0);
  if (minConfidence && minConfidence > 0) {
    args.push("--min-confidence", String(minConfidence));
  }
  return args;
}

function runCodequal(args: string[], cwd: string): Promise<ScanPayload> {
  const bin = config().get<string>("path", "codequal") || "codequal";
  return new Promise((resolve, reject) => {
    execFile(
      bin,
      args,
      { cwd, maxBuffer: 64 * 1024 * 1024, env: process.env },
      (error, stdout, stderr) => {
        const text = (stdout || "").trim();
        if (text) {
          try {
            resolve(JSON.parse(text) as ScanPayload);
            return;
          } catch (parseErr) {
            reject(new Error(`Could not parse CodeQual output: ${String(parseErr)}`));
            return;
          }
        }
        reject(new Error(stderr?.trim() || error?.message || "CodeQual produced no output"));
      }
    );
  });
}

function severityToVS(severity: Finding["severity"]): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

function toDiagnostic(f: Finding): vscode.Diagnostic {
  const start = Math.max(0, (f.line || 1) - 1);
  const end = Math.max(start, (f.end_line || f.line || 1) - 1);
  const range = new vscode.Range(start, 0, end, Number.MAX_SAFE_INTEGER);
  let message = `${f.title}  [${f.severity} · ${f.category}]`;
  if (f.description) {
    message += `\n${f.description}`;
  }
  if (f.suggestion) {
    message += `\n💡 ${f.suggestion}`;
  }
  const diag = new vscode.Diagnostic(range, message, severityToVS(f.severity));
  diag.source = "CodeQual";
  diag.code = f.rule_id;
  return diag;
}

async function scanActiveFile(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showInformationMessage("CodeQual: open a file to scan.");
    return;
  }
  await scanDocument(editor.document);
}

async function scanDocument(doc: vscode.TextDocument): Promise<void> {
  if (doc.uri.scheme !== "file" || doc.isUntitled) {
    return;
  }
  const filePath = doc.uri.fsPath;
  const cwd = vscode.workspace.getWorkspaceFolder(doc.uri)?.uri.fsPath || path.dirname(filePath);

  status.text = "$(sync~spin) CodeQual";
  try {
    const payload = await runCodequal(["file", filePath, ...commonArgs()], cwd);
    const diags = payload.findings.map(toDiagnostic);
    diagnostics.set(doc.uri, diags);
    status.text = `$(shield) CodeQual: ${diags.length}`;
    output.appendLine(
      `[${payload.mode}] ${path.basename(filePath)} — ${diags.length} finding(s)`
    );
  } catch (err) {
    status.text = "$(shield) CodeQual";
    reportError(err);
  }
}

async function scanWorkspace(): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showInformationMessage("CodeQual: open a folder to scan.");
    return;
  }
  const root = folders[0].uri.fsPath;

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: "CodeQual: scanning workspace…" },
    async () => {
      try {
        const payload = await runCodequal(["repo", root, ...commonArgs()], root);
        diagnostics.clear();
        const byFile = new Map<string, vscode.Diagnostic[]>();
        for (const f of payload.findings) {
          const abs = path.isAbsolute(f.file) ? f.file : path.join(root, f.file);
          const list = byFile.get(abs) || [];
          list.push(toDiagnostic(f));
          byFile.set(abs, list);
        }
        for (const [abs, diags] of byFile) {
          diagnostics.set(vscode.Uri.file(abs), diags);
        }
        vscode.window.showInformationMessage(
          `CodeQual [${payload.mode}]: ${payload.total_findings} finding(s) across ${payload.files_scanned} file(s).`
        );
        status.text = `$(shield) CodeQual: ${payload.total_findings}`;
      } catch (err) {
        reportError(err);
      }
    }
  );
}

function reportError(err: unknown): void {
  const message = err instanceof Error ? err.message : String(err);
  output.appendLine(`ERROR: ${message}`);
  vscode.window.showErrorMessage(
    `CodeQual failed: ${message}. Ensure the 'codequal' CLI is installed (pip install codequal) ` +
      `or set "codequal.path" in settings.`
  );
}
