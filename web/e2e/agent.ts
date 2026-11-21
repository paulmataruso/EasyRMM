// An enrolled device's EasyRMM agent, as far as the suite needs one: it signs its requests the way the real agent does
// (internal/agentproto: Ed25519 over the method, target, time, a nonce and the body's SHA-256), so the server cannot tell
// it apart, and asks for work, starts it and reports its result.

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
  script: string;
  args: string[];
  timeoutSeconds: number;
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

  /** The jobs waiting for the device. The server holds the poll open for a while when there are none. */
  async poll(): Promise<JobPayload[]> {
    const { jobs } = (await (await this.post("/api/agent/v1/jobs/poll", {})).json()) as { jobs: { payload: string }[] };
    return jobs.map((j) => JSON.parse(Buffer.from(j.payload, "base64").toString("utf8")) as JobPayload);
  }

  /** Whether the server lets the run start now. */
  async start(runId: string): Promise<boolean> {
    return ((await (await this.post(`/api/agent/v1/jobs/${runId}/start`, {})).json()) as { proceed: boolean }).proceed;
  }

  /** Reports that the run ended with exit code 0 and this output. */
  async succeeded(runId: string, stdout: string): Promise<void> {
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
    });
  }
}
