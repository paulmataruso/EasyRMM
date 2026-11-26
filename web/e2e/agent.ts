// An enrolled device's EasyRMM agent, as far as the suite needs one: it signs its requests the way the real agent does
// (internal/agentproto: Ed25519 over the method, target, time, a nonce and the body's SHA-256), so the server cannot tell
// it apart, asks for work, starts it and reports its result, and reports its inventory and its disks' health.

import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import type { APIRequestContext } from "@playwright/test";

/** A device's key pair, and the public half as enrollment sends it: the raw Ed25519 key, base64. */
export function deviceKey(): { privateKey: KeyObject; publicKey: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicKey: publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64") };
}

/** What the server asks a device to run (agentproto.JobPayload). */
export interface JobPayload {
  runId: string;
  jobId: string;
  deviceId: string;
  shell: string;
  /** A PowerShell 7 script that may run in Windows PowerShell 5.1 (ADR-0064). */
  pwshFallback?: boolean;
  script: string;
  args: string[];
  timeoutSeconds: number;
}

/** The program a run started, as the agent reports it with the result (agentproto.Interpreter). */
export interface Interpreter {
  edition?: "Desktop" | "Core";
  version?: string;
  arch?: "x64" | "arm64" | "x86";
  path: string;
  fallback?: boolean;
}

/** A PowerShell the agent found, as its inventory lists it (agentproto.PowerShellInstall). */
export interface PowerShellInstall extends Interpreter {
  edition: "Desktop" | "Core";
  version: string;
  usable: boolean;
  reason?: string;
}

export class Agent {
  constructor(
    private readonly request: APIRequestContext,
    readonly deviceId: string,
    private readonly key: KeyObject,
  ) {}

  private async post(target: string, body: unknown) {
    const raw = Buffer.from(JSON.stringify(body));
    const ts = Math.floor(Date.now() / 1000);
    const nonce = randomBytes(18).toString("base64url");
    const message = ["EASYRMM-AGENT-SIG-V1", "POST", target, String(ts), nonce, createHash("sha256").update(raw).digest("hex")].join("\n");
    const sig = sign(null, Buffer.from(message), this.key).toString("base64url");
    const response = await this.request.post(target, {
      data: raw,
      headers: { "Content-Type": "application/json", Authorization: `EasyRMM-Agent device=${this.deviceId}, ts=${ts}, nonce=${nonce}, sig=${sig}` },
    });
    if (!response.ok()) throw new Error(`POST ${target}: ${response.status()} ${await response.text()}`);
    return response;
  }

  /**
   * The jobs waiting for the device. The server holds the poll open for a while when there are none. accepts lists the
   * job capabilities this agent's build takes ("job.pwsh"); without it the device's last list stands (ADR-0064).
   */
  async poll(accepts?: string[]): Promise<JobPayload[]> {
    const { jobs } = (await (await this.post("/api/agent/v1/jobs/poll", accepts ? { accepts } : {})).json()) as { jobs: { payload: string }[] };
    return jobs.map((j) => JSON.parse(Buffer.from(j.payload, "base64").toString("utf8")) as JobPayload);
  }

  /** A heartbeat with these facts (agentproto.HeartbeatRequest): the device checks in. */
  async heartbeat(facts: unknown): Promise<void> {
    const r = await this.post("/api/agent/v1/heartbeat", { facts });
    if (!r.ok()) throw new Error(`heartbeat: ${r.status()} ${await r.text()}`);
  }

  /** Whether the server lets the run start now. */
  async start(runId: string): Promise<boolean> {
    return ((await (await this.post(`/api/agent/v1/jobs/${runId}/start`, {})).json()) as { proceed: boolean }).proceed;
  }

  /** Sends the device's inventory (agentproto.Inventory), as the agent does at start and when it changes. */
  async inventory(inventory: unknown): Promise<void> {
    await this.post("/api/agent/v1/inventory", inventory);
  }

  /**
   * Sends a hardware report (agentproto.HardwareReport, ADR-0065): each disk's facts as read, each fact
   * `{state, reason?, value?}` with state read, unknown, unsupported or unavailable. The server judges them.
   */
  async hardware(report: { disks: unknown[] }): Promise<void> {
    await this.post("/api/agent/v1/hardware", report);
  }

  /**
   * A heartbeat (agentproto.HeartbeatRequest) with the facts given, and what else the agent reports with it: the
   * Defender state and the installed files' hashes (ADR-0070). Returns the server's answer.
   */
  async heartbeat(request: { facts: unknown; defender?: unknown; installedFiles?: unknown }): Promise<{ defender?: { enabled: boolean } }> {
    return (await (await this.post("/api/agent/v1/heartbeat", request)).json()) as { defender?: { enabled: boolean } };
  }

  /** Reports that the run ended with exit code 0 and this output, and the program it started when given. */
  async succeeded(runId: string, stdout: string, interpreter?: Interpreter): Promise<void> {
    const now = new Date().toISOString();
    await this.post(`/api/agent/v1/jobs/${runId}/result`, {
      status: "succeeded",
      exitCode: 0,
      stdout,
      stderr: "",
      stdoutTruncated: false,
      stderrTruncated: false,
      error: "",
      startedAt: now,
      finishedAt: now,
      ...(interpreter ? { interpreter } : {}),
    });
  }
}
