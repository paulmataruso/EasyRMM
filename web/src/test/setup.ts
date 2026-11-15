import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, expect, vi } from "vitest";
import { setAuthErrorListener, setCsrfToken } from "../api/client";
import { takeUnmatched } from "./fakeApi";

// jsdom does not lay out, so it has no scrollIntoView; j/k row travel calls it.
Element.prototype.scrollIntoView ??= function scrollIntoView() {};

afterEach(() => {
  cleanup();
  setCsrfToken(null);
  setAuthErrorListener(null);
  vi.unstubAllGlobals();
  window.localStorage.clear();
  expect(takeUnmatched(), "requests with no fake API route").toEqual([]);
});
