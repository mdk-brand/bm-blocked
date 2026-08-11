import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

process.env.BM_BLOCKED_DISABLE_SERVER = "1";
process.env.BM_BLOCKED_TRUSTED_SESSION_SECRET = Buffer.alloc(32, 7).toString("base64");

const {
  buildReversedBlockedSites,
  buildChannelReportDefinition,
  createSessionToken,
  decryptRememberedTokenPayload,
  encryptRememberedTokenPayload,
  getLastDaysRange,
  getLast30DaysRange,
  migrateOperationHistoryFile,
  normalizeChannelPlacement,
  normalizeChannelSettings,
  parseChannelPerformanceReport,
  selectChannelsForAvailableSlots,
} = await import("./server.js");

test("migrates legacy operation history once without overwriting new history", async (context) => {
  const testDirectory = await fs.mkdtemp(
    path.join(os.tmpdir(), "bm-blocked-history-test-"),
  );
  const legacyPath = path.join(testDirectory, "legacy", "operation-history.json");
  const currentPath = path.join(testDirectory, "current", "operation-history.json");
  const legacyHistory = JSON.stringify({ schemaVersion: 1, operations: [{ operationId: "old" }] });
  const currentHistory = JSON.stringify({ schemaVersion: 1, operations: [{ operationId: "new" }] });

  context.after(() => fs.rm(testDirectory, { recursive: true, force: true }));
  await fs.mkdir(path.dirname(legacyPath), { recursive: true });
  await fs.writeFile(legacyPath, legacyHistory, "utf8");

  assert.equal(await migrateOperationHistoryFile(legacyPath, currentPath), true);
  assert.equal(await fs.readFile(currentPath, "utf8"), legacyHistory);

  await fs.writeFile(currentPath, currentHistory, "utf8");
  assert.equal(await migrateOperationHistoryFile(legacyPath, currentPath), false);
  assert.equal(await fs.readFile(currentPath, "utf8"), currentHistory);
});

test("creates a session that expires exactly seven days after login", () => {
  const now = Date.UTC(2026, 7, 11, 9, 0, 0);
  const session = createSessionToken(now);
  const encodedPayload = session.value.split(".")[0];
  const payload = JSON.parse(
    Buffer.from(encodedPayload, "base64url").toString("utf8"),
  );

  assert.equal(session.expiresAt, now + 7 * 24 * 60 * 60 * 1000);
  assert.equal(payload.expiresAt, session.expiresAt);
});

test("encrypts a remembered OAuth token without storing it as plain text", () => {
  const key = Buffer.alloc(32, 11);
  const token = "yandex-oauth-secret-token";
  const expiresAt = Date.UTC(2026, 7, 18, 9, 0, 0);
  const encrypted = encryptRememberedTokenPayload(token, expiresAt, key);

  assert.equal(JSON.stringify(encrypted).includes(token), false);
  assert.deepEqual(decryptRememberedTokenPayload(encrypted, key), {
    token,
    expiresAt,
  });
});

test("rejects a remembered token file with a changed expiration", () => {
  const key = Buffer.alloc(32, 13);
  const encrypted = encryptRememberedTokenPayload(
    "another-secret-token",
    Date.UTC(2026, 7, 18, 9, 0, 0),
    key,
  );

  assert.throws(
    () => decryptRememberedTokenPayload(
      { ...encrypted, expiresAt: encrypted.expiresAt + 1000 },
      key,
    ),
  );
});

test("reverses channel blocking without removing later exclusions", () => {
  const result = buildReversedBlockedSites(
    "block-channels",
    ["example.ru", "t.me/blocked-by-service", "later-added.ru"],
    ["t.me/blocked-by-service"],
  );

  assert.deepEqual(result, {
    blockedSites: ["example.ru", "later-added.ru"],
    changedCount: 1,
    exceedsLimit: false,
  });
});

test("reverses placement clearing without duplicating restored exclusions", () => {
  const result = buildReversedBlockedSites(
    "clear",
    ["existing.ru", "already-restored.ru"],
    ["removed.ru", "already-restored.ru"],
  );

  assert.deepEqual(result, {
    blockedSites: ["existing.ru", "already-restored.ru", "removed.ru"],
    changedCount: 1,
    exceedsLimit: false,
  });
});

test("puts custom report dates inside SelectionCriteria", () => {
  const definition = buildChannelReportDefinition(
    [{ campaignId: "101" }, { campaignId: "202" }],
    "2026-07-08",
    "2026-08-06",
  );

  assert.equal(definition.DateFrom, undefined);
  assert.equal(definition.DateTo, undefined);
  assert.equal(definition.SelectionCriteria.DateFrom, "2026-07-08");
  assert.equal(definition.SelectionCriteria.DateTo, "2026-08-06");
  assert.deepEqual(definition.SelectionCriteria.Filter[0].Values, ["101", "202"]);
});

test("recognizes supported channel placements with a non-empty path", () => {
  assert.equal(normalizeChannelPlacement("t.me/example")?.placement, "t.me/example");
  assert.equal(
    normalizeChannelPlacement("web.max.ru/company/news?from=report")?.placement,
    "web.max.ru/company/news",
  );
  assert.equal(normalizeChannelPlacement("vk.com/brand")?.placement, "vk.com/brand");
  assert.equal(normalizeChannelPlacement("rutube.ru/channel/123")?.placement, "rutube.ru/channel/123");
  assert.equal(normalizeChannelPlacement("t.me"), null);
  assert.equal(normalizeChannelPlacement("https://t.me/example"), null);
  assert.equal(normalizeChannelPlacement("www.vk.com/brand"), null);
  assert.equal(normalizeChannelPlacement("news.t.me/example"), null);
  assert.equal(normalizeChannelPlacement("example.ru/channel"), null);
});

test("aggregates channel costs and keeps only costs strictly above 15", () => {
  const campaigns = [
    {
      campaignId: "101",
      blockedSites: ["t.me/already-blocked"],
    },
    {
      campaignId: "202",
      blockedSites: [],
    },
  ];
  const report = [
    "101\tt.me/company\t10.00",
    "101\tt.me/company\t5.01",
    "101\tvk.com/exactly-fifteen\t15.00",
    "101\tweb.max.ru/company\t75.40",
    "101\tt.me/already-blocked\t120.00",
    "101\texample.ru/not-a-channel\t999.00",
    "202\trutube.ru/channel/42\t51.00",
  ].join("\n");

  const parsed = parseChannelPerformanceReport(report, campaigns);

  assert.deepEqual(
    parsed.get("101").map(({ placement, cost, isBlocked }) => ({
      placement,
      cost,
      isBlocked,
    })),
    [
      { placement: "web.max.ru/company", cost: 75.4, isBlocked: undefined },
      { placement: "t.me/company", cost: 15.01, isBlocked: undefined },
    ],
  );
  assert.equal(parsed.get("202")[0].placement, "rutube.ru/channel/42");
});

test("keeps the highest-cost channels when exclusion slots are limited", () => {
  const channels = [
    { placement: "t.me/low", cost: 51 },
    { placement: "vk.com/high", cost: 400 },
    { placement: "max.ru/middle", cost: 120 },
  ];
  const result = selectChannelsForAvailableSlots(channels, 998);

  assert.deepEqual(
    result.selected.map((channel) => channel.placement),
    ["vk.com/high", "max.ru/middle"],
  );
  assert.deepEqual(
    result.skipped.map((channel) => channel.placement),
    ["t.me/low"],
  );
});

test("builds an inclusive 30-day Moscow report range", () => {
  assert.deepEqual(getLast30DaysRange(new Date("2026-08-06T12:00:00Z")), {
    dateFrom: "2026-07-08",
    dateTo: "2026-08-06",
  });
});

test("builds a configurable inclusive report range", () => {
  assert.deepEqual(getLastDaysRange(7, new Date("2026-08-06T12:00:00Z")), {
    dateFrom: "2026-07-31",
    dateTo: "2026-08-06",
  });
});

test("uses a custom threshold and selected supported channel prefixes", () => {
  const settings = normalizeChannelSettings({
    costThreshold: 25.5,
    periodDays: 14,
    prefixes: ["t.me/", "vk.com/"],
  });
  const campaigns = [{ campaignId: "101", blockedSites: [] }];
  const report = [
    "101\tt.me/working\t25.51",
    "101\tmax.ru/not-selected\t100.00",
    "101\tt.me/exact-threshold\t25.50",
  ].join("\n");
  const parsed = parseChannelPerformanceReport(report, campaigns, settings);

  assert.deepEqual(
    parsed.get("101").map((channel) => channel.placement),
    ["t.me/working"],
  );
});

test("allows disabling every channel prefix", () => {
  assert.deepEqual(
    normalizeChannelSettings({
      costThreshold: 15,
      periodDays: 30,
      prefixes: [],
    }).prefixes,
    [],
  );
});

test("rejects channel prefixes outside the fixed list", () => {
  assert.throws(
    () => normalizeChannelSettings({
      costThreshold: 15,
      periodDays: 30,
      prefixes: ["example.ru/channels/"],
    }),
    /поддерживаемые префиксы/,
  );
});
