import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fail, installFakeApi, noContent, ok } from "../test/fakeApi";
import { api, ApiError, buildQuery, errorMessage, fieldError, request, setAuthErrorListener, setCsrfToken } from "./client";

beforeEach(() => setCsrfToken(null));
afterEach(() => {
  setAuthErrorListener(null);
  vi.unstubAllGlobals();
});

describe("buildQuery", () => {
  it("skips empty values and encodes the rest", () => {
    expect(buildQuery({ q: "a b", empty: "", none: null, missing: undefined, n: 0, flag: false })).toBe("?q=a+b&n=0&flag=false");
    expect(buildQuery({})).toBe("");
    expect(buildQuery()).toBe("");
  });
});

describe("errorMessage and fieldError", () => {
  it("names the single field problem of a validation error", () => {
    const e = new ApiError(400, "validation_failed", "The request is invalid.", { email: "Enter a valid email address." });
    expect(errorMessage(e)).toBe("Enter a valid email address.");
    expect(fieldError(e, "email")).toBe("Enter a valid email address.");
    expect(fieldError(e, "name")).toBeNull();
  });

  it("uses the server message when several fields failed", () => {
    const e = new ApiError(400, "validation_failed", "The request is invalid.", { a: "x", b: "y" });
    expect(errorMessage(e)).toBe("The request is invalid.");
  });

  it("handles plain errors and unknown values", () => {
    expect(errorMessage(new Error("boom"))).toBe("boom");
    expect(errorMessage("nope")).toBe("Something went wrong.");
    expect(fieldError(new Error("x"), "a")).toBeNull();
  });
});

describe("request", () => {
  it("sends the CSRF token on unsafe methods only", async () => {
    const server = installFakeApi({ "GET /things": ok({ items: [] }), "POST /things": ok({ id: "1" }) });
    setCsrfToken("token-a");
    await api.get("/things");
    await api.post("/things", { name: "x" });
    const get = server.call("GET /things");
    const post = server.call("POST /things");
    expect(get.headers["x-csrf-token"]).toBeUndefined();
    expect(post.headers["x-csrf-token"]).toBe("token-a");
    expect(post.headers["content-type"]).toBe("application/json");
    expect(post.body).toEqual({ name: "x" });
  });

  it("passes query parameters through", async () => {
    const server = installFakeApi({ "GET /audit": ok({ items: [] }) });
    await api.get("/audit", { organizationId: "o1", action: "", limit: 100 });
    expect(server.call("GET /audit").query.toString()).toBe("organizationId=o1&limit=100");
  });

  it("turns the error envelope into an ApiError", async () => {
    installFakeApi({ "POST /organizations": fail(409, "conflict", "That name is taken.", { name: "Choose another name." }) });
    const error = await api.post("/organizations", { name: "x" }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 409, code: "conflict", message: "That name is taken.", fields: { name: "Choose another name." } });
  });

  it("falls back to a generic message when the body is not the envelope", async () => {
    installFakeApi({ "GET /broken": { status: 502, body: "bad gateway" } });
    const error = (await api.get("/broken").catch((e: unknown) => e)) as ApiError;
    expect(error.code).toBe("server_error");
    expect(error.message).toBe("The server encountered an error. Try again later.");
  });

  it("reports network failures as status 0", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    const error = (await api.get("/x").catch((e: unknown) => e)) as ApiError;
    expect(error.status).toBe(0);
    expect(error.code).toBe("network_error");
  });

  it("rethrows aborts untouched", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new DOMException("aborted", "AbortError")));
    await expect(api.get("/x")).rejects.toMatchObject({ name: "AbortError" });
  });

  it("returns undefined for 204", async () => {
    installFakeApi({ "DELETE /things/:id": noContent });
    await expect(api.del("/things/1")).resolves.toBeUndefined();
  });

  it("refreshes the CSRF token once and retries when the session rotated", async () => {
    setCsrfToken("stale");
    let attempts = 0;
    const server = installFakeApi({
      "GET /auth/session": ok({ csrfToken: "fresh" }),
      "POST /things": (req) => {
        attempts++;
        return req.headers["x-csrf-token"] === "fresh" ? ok({ id: "1" }) : fail(403, "csrf_failed", "Refresh and try again.");
      },
    });
    await expect(api.post("/things", {})).resolves.toEqual({ id: "1" });
    expect(attempts).toBe(2);
    expect(server.callsTo("GET /auth/session")).toHaveLength(1);
  });

  it("gives up after one CSRF retry", async () => {
    setCsrfToken("stale");
    const server = installFakeApi({
      "GET /auth/session": ok({ csrfToken: "fresh" }),
      "POST /things": fail(403, "csrf_failed", "Refresh and try again."),
    });
    await expect(api.post("/things", {})).rejects.toMatchObject({ code: "csrf_failed" });
    expect(server.callsTo("POST /things")).toHaveLength(2);
  });

  it("tells the auth listener when the session ended or needs its second factor", async () => {
    const listener = vi.fn();
    setAuthErrorListener(listener);
    installFakeApi({
      "GET /gone": fail(401, "unauthenticated", "Sign in."),
      "GET /mfa": fail(403, "mfa_required", "Second factor needed."),
      "GET /denied": fail(403, "forbidden", "Not allowed."),
    });
    await api.get("/gone").catch(() => undefined);
    await api.get("/mfa").catch(() => undefined);
    await api.get("/denied").catch(() => undefined);
    expect(listener.mock.calls.map(([e]) => (e as ApiError).code)).toEqual(["unauthenticated", "mfa_required"]);
  });

  it("stays silent for sign-in screens", async () => {
    const listener = vi.fn();
    setAuthErrorListener(listener);
    installFakeApi({ "POST /auth/login": fail(401, "unauthenticated", "Wrong email or password.") });
    await request("POST", "/auth/login", { body: {}, silentAuth: true }).catch(() => undefined);
    expect(listener).not.toHaveBeenCalled();
  });
});
