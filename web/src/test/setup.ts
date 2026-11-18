import "@testing-library/jest-dom/vitest";
import { cleanup, configure } from "@testing-library/react";
import { afterEach, expect, vi } from "vitest";
import { setAuthErrorListener, setCsrfToken } from "../api/client";
import { takeUnmatched } from "./fakeApi";

// A file's first render, cold and under coverage on a busy runner, can take
// longer than findBy*'s 1 second default.
configure({ asyncUtilTimeout: 5_000 });

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
