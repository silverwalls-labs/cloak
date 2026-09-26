/**
 * Config serialization tests: JS object → TOML → engine accepts it.
 */

import { describe, it, before } from "node:test";
import assert from "node:assert/strict";

import { configToToml } from "../src/config.ts";
import { createEngine } from "../src/index.ts";

// ── Unit: configToToml ─────────────────────────────────────────────

describe("configToToml", () => {
  it("serializes redaction section", () => {
    const toml = configToToml({
      redaction: { digestKey: "env:CLOAK_DIGEST_KEY" },
    });
    assert.ok(toml.includes("[redaction]"));
    assert.ok(toml.includes('digest_key = "env:CLOAK_DIGEST_KEY"'));
  });

  it("serializes rule overrides", () => {
    const toml = configToToml({
      rules: { "phone-intl": { enabled: false } },
    });
    assert.ok(toml.includes("[rules.phone-intl]"));
    assert.ok(toml.includes("enabled = false"));
  });

  it("serializes full config", () => {
    const toml = configToToml({
      redaction: { digestKey: "env:MY_KEY" },
      rules: {
        "phone-intl": { enabled: false },
        "credit-card": { enabled: true },
      },
    });
    assert.ok(toml.includes('[redaction]\ndigest_key = "env:MY_KEY"'));
    assert.ok(toml.includes("[rules.phone-intl]\nenabled = false"));
    assert.ok(toml.includes("[rules.credit-card]\nenabled = true"));
  });

  it("returns empty string for empty config", () => {
    assert.equal(configToToml({}), "");
  });

  it("escapes special characters in values", () => {
    const toml = configToToml({
      redaction: { digestKey: 'has "quotes" and\nnewlines' },
    });
    assert.ok(toml.includes('\\"quotes\\"'));
    assert.ok(toml.includes("\\n"));
  });

  it("rejects rule IDs with dots", () => {
    assert.throws(
      () => configToToml({ rules: { "my.rule": { enabled: false } } }),
      /invalid rule ID/,
    );
  });

  it("rejects rule IDs with brackets", () => {
    assert.throws(
      () => configToToml({ rules: { "my]rule": { enabled: false } } }),
      /invalid rule ID/,
    );
  });

  it("rejects uppercase rule IDs", () => {
    assert.throws(
      () => configToToml({ rules: { "MyRule": { enabled: false } } }),
      /invalid rule ID/,
    );
  });
});

// ── Integration: round-trip through engine ─────────────────────────

describe("config round-trip", () => {
  it("JS object config accepted by engine", async () => {
    const engine = await createEngine(
      { redaction: { digestKey: "env:CLOAK_DIGEST_KEY" } },
      { CLOAK_DIGEST_KEY: "test-key" },
    );
    const { output } = engine.redact("hello world");
    assert.equal(output.toString(), "hello world");
    engine.dispose();
  });

  it("TOML string config accepted by engine", async () => {
    const engine = await createEngine(
      '[redaction]\ndigest_key = "env:CLOAK_DIGEST_KEY"\n',
      { CLOAK_DIGEST_KEY: "test-key" },
    );
    const { output } = engine.redact("hello world");
    assert.equal(output.toString(), "hello world");
    engine.dispose();
  });

  it("empty config accepted (ephemeral key)", async () => {
    const engine = await createEngine();
    const { output } = engine.redact("hello world");
    assert.equal(output.toString(), "hello world");
    engine.dispose();
  });

  it("config with disabled rule skips detection", async () => {
    const engine = await createEngine(
      {
        redaction: { digestKey: "env:CLOAK_DIGEST_KEY" },
        rules: { "phone-intl": { enabled: false } },
      },
      { CLOAK_DIGEST_KEY: "test-key" },
    );
    // phone-intl is disabled; other rules still work.
    const { output } = engine.redact(
      "token=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",
    );
    assert.ok(
      output.toString().includes("[CLOAK:github-token:"),
      "github-token should still be redacted",
    );
    engine.dispose();
  });
});
