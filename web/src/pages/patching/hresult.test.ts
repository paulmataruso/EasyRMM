import { describe, expect, it } from "vitest";
import { explainCode, hresultHex } from "./hresult";

describe("error codes", () => {
  it("reads hex in any case, and signed or unsigned decimals, as hex", () => {
    expect(hresultHex("0x80240022")).toBe("0x80240022");
    expect(hresultHex("0x8024402c")).toBe("0x8024402C");
    expect(hresultHex(" 0X80070643 ")).toBe("0x80070643");
    expect(hresultHex("-2147023293")).toBe("0x80070643");
    expect(hresultHex("2149842978")).toBe("0x80240022");
    expect(hresultHex("0")).toBe("0x00000000");
    expect(explainCode("0")).toMatchObject({ kind: "known", meaning: "No error." });
  });

  it("leaves codes that are not numbers, or too large, alone", () => {
    expect(hresultHex("apt_exit_100")).toBeNull();
    expect(hresultHex("")).toBeNull();
    expect(hresultHex("0x123456789")).toBeNull();
    expect(hresultHex("4294967296")).toBeNull();
    expect(hresultHex("-2147483649")).toBeNull();
  });

  it("explains the common Windows Update codes", () => {
    for (const code of ["0x80240022", "0x8024402C", "0x80070643", "0x800F0922", "0x80073712", "0x80070070", "0x80240016"]) {
      const e = explainCode(code);
      expect(e.kind, code).toBe("known");
    }
    expect(explainCode("0x8024402c")).toEqual({
      kind: "known",
      hex: "0x8024402C",
      meaning: "The name of the update server or proxy could not be resolved.",
      advice: "Check the device's DNS and proxy settings.",
    });
    expect(explainCode("-2147023293")).toMatchObject({ kind: "known", hex: "0x80070643" });
  });

  it("says which codes it does not know, and whether they are Windows Update's", () => {
    expect(explainCode("0x80249999")).toEqual({ kind: "unknown", hex: "0x80249999", windowsUpdate: true });
    expect(explainCode("0x87D00324")).toEqual({ kind: "unknown", hex: "0x87D00324", windowsUpdate: false });
    expect(explainCode("apt_exit_100")).toEqual({ kind: "other", code: "apt_exit_100" });
  });
});
