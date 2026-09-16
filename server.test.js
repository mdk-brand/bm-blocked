import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test, { after } from "node:test";
import { fileURLToPath } from "node:url";

process.env.BM_BLOCKED_DISABLE_SERVER = "1";
process.env.BM_BLOCKED_TRUSTED_SESSION_SECRET = Buffer.alloc(32, 7).toString("base64");
const settingsTestDirectory = await fs.mkdtemp(
  path.join(os.tmpdir(), "bm-blocked-live-settings-test-"),
);
process.env.BM_BLOCKED_USER_DATA_DIR = settingsTestDirectory;
await fs.writeFile(
  path.join(settingsTestDirectory, "settings.json"),
  JSON.stringify({ costThreshold: 15, periodDays: 30, prefixes: ["t.me/"] }),
  "utf8",
);
after(() => fs.rm(settingsTestDirectory, {
  recursive: true,
  force: true,
  maxRetries: 3,
  retryDelay: 20,
}));

const {
  addProtectedPlacement,
  buildReversedBlockedSites,
  buildChannelReportDefinition,
  createSessionToken,
  decryptRememberedTokenPayload,
  encryptRememberedTokenPayload,
  filterProtectedChannels,
  getLastDaysRange,
  getLast30DaysRange,
  migrateOperationHistoryFile,
  normalizeAppPlacement,
  normalizeChannelPlacement,
  normalizeChannelSettings,
  normalizeClients,
  normalizeProtectedPlacement,
  normalizeTrackedPlacement,
  parseChannelPerformanceReport,
  persistChannelSettings,
  removeProtectedPlacement,
  saveChannelSettings,
  selectChannelsForAvailableSlots,
} = await import("./server.js");

test("restores saved settings with app exclusions on a fresh start", async (context) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "bm-blocked-startup-settings-"));
  const settingsPath = path.join(directory, "settings.json");
  context.after(() => fs.rm(directory, { recursive: true, force: true }));
  await fs.writeFile(settingsPath, JSON.stringify({
    costThreshold: 5,
    maxCostThreshold: 500,
    periodDays: 21,
    prefixes: ["t.me/"],
    includeApps: true,
    protectedPlacements: ["com.example.game"],
  }));

  const child = spawnSync(process.execPath, [
    "--input-type=module",
    "-e",
    "const { toPublicChannelSettings } = await import('./server.js'); process.stdout.write(JSON.stringify(toPublicChannelSettings()));",
  ], {
    cwd: path.dirname(fileURLToPath(import.meta.url)),
    env: { ...process.env, BM_BLOCKED_USER_DATA_DIR: directory },
    encoding: "utf8",
    timeout: 15000,
  });

  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stderr, "");
  const restored = JSON.parse(child.stdout);
  assert.equal(restored.costThreshold, 5);
  assert.equal(restored.maxCostThreshold, 500);
  assert.equal(restored.periodDays, 21);
  assert.equal(restored.includeApps, true);
  assert.deepEqual(restored.protectedPlacements, ["com.example.game"]);
  assert.deepEqual(restored.prefixes, ["t.me/", "max.ru/", "web.max.ru/", "vk.com/", "rutube.ru/"]);
  assert.deepEqual(JSON.parse(await fs.readFile(settingsPath, "utf8")), restored);
});

test("keeps active clients and excludes archived clients", () => {
  const clients = normalizeClients([
    { ClientId: 1, Login: "active", ClientInfo: "Активный", Archived: "NO" },
    { ClientId: 2, Login: "archived", ClientInfo: "Архивный", Archived: "YES" },
  ]);

  assert.deepEqual(clients, [
    { id: "1", login: "active", name: "Активный (active)" },
  ]);
  assert.deepEqual(normalizeClients([{ Login: "archived", Archived: "YES" }]), []);
});

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
    maxCostThreshold: 80,
    periodDays: 14,
    prefixes: ["t.me/", "vk.com/"],
  });
  const campaigns = [{ campaignId: "101", blockedSites: [] }];
  const report = [
    "101\tt.me/working\t25.51",
    "101\tvk.com/at-upper-threshold\t80.00",
    "101\tvk.com/above-upper-threshold\t80.01",
    "101\tmax.ru/not-selected\t100.00",
    "101\tt.me/exact-threshold\t25.50",
  ].join("\n");
  const parsed = parseChannelPerformanceReport(report, campaigns, settings);

  assert.deepEqual(
    parsed.get("101").map((channel) => channel.placement),
    ["vk.com/at-upper-threshold", "t.me/working"],
  );
});

test("keeps existing lower threshold when new settings fields are absent", () => {
  const settings = normalizeChannelSettings({
    costThreshold: 5,
    periodDays: 30,
    prefixes: ["t.me/"],
  });

  assert.equal(settings.costThreshold, 5);
  assert.equal(settings.maxCostThreshold, 1000000);
  assert.equal(settings.includeApps, false);
});

test("persists the complete channel settings without resetting the lower threshold", async (context) => {
  const testDirectory = await fs.mkdtemp(
    path.join(os.tmpdir(), "bm-blocked-settings-test-"),
  );
  const settingsPath = path.join(testDirectory, "settings.json");

  context.after(() => fs.rm(testDirectory, {
    recursive: true,
    force: true,
    maxRetries: 3,
    retryDelay: 20,
  }));
  await persistChannelSettings(settingsPath, {
    costThreshold: 5,
    maxCostThreshold: 240,
    periodDays: 21,
    prefixes: ["t.me/", "max.ru/"],
    includeApps: true,
    protectedPlacements: ["max.ru/join/Keep", "com.example.game"],
  });

  const restored = normalizeChannelSettings(
    JSON.parse(await fs.readFile(settingsPath, "utf8")),
  );

  assert.deepEqual(restored, {
    costThreshold: 5,
    maxCostThreshold: 240,
    periodDays: 21,
    prefixes: ["t.me/", "max.ru/"],
    includeApps: true,
    protectedPlacements: ["max.ru/join/Keep", "com.example.game"],
  });
});

test("keeps legacy settings valid with an empty persistent exclusion list", () => {
  const settings = normalizeChannelSettings({
    costThreshold: 5,
    periodDays: 30,
    prefixes: ["t.me/"],
  });

  assert.equal(settings.costThreshold, 5);
  assert.deepEqual(settings.protectedPlacements, []);
});

test("normalizes exact protected placements regardless of enabled checks", () => {
  const settings = normalizeChannelSettings({
    costThreshold: 15,
    periodDays: 30,
    prefixes: [],
    includeApps: false,
    protectedPlacements: [
      "MAX.ru/join/Keep",
      "max.ru/join/keep",
      "com.example.game",
    ],
  });

  assert.deepEqual(settings.protectedPlacements, [
    "max.ru/join/keep",
    "com.example.game",
  ]);
  assert.equal(normalizeProtectedPlacement("max.ru/join/Keep")?.key, "max.ru/join/keep");
  assert.equal(normalizeProtectedPlacement("ordinary-site.ru"), null);
});

test("ignores protected candidates across every campaign but keeps nearby paths", () => {
  const settings = normalizeChannelSettings({
    costThreshold: 15,
    periodDays: 30,
    prefixes: ["max.ru/"],
    includeApps: true,
    protectedPlacements: ["max.ru/join/Keep", "com.example.game"],
  });
  const campaigns = [
    { campaignId: "101", blockedSites: [] },
    { campaignId: "202", blockedSites: [] },
  ];
  const report = [
    "101\tmax.ru/join/Keep\t100.00",
    "202\tmax.ru/join/keep\t120.00",
    "101\tmax.ru/join/Other\t20.00",
    "101\tcom.example.game\t50.00",
    "202\tcom.example.other\t30.00",
  ].join("\n");
  const parsed = parseChannelPerformanceReport(report, campaigns, settings);

  assert.deepEqual(parsed.get("101").map((channel) => channel.placement), [
    "max.ru/join/Other",
  ]);
  assert.deepEqual(parsed.get("202").map((channel) => channel.placement), [
    "com.example.other",
  ]);
});

test("removes a newly protected placement from an already formed report", () => {
  const report = {
    campaigns: [
      { campaignId: "101", channels: [
        { key: "max.ru/join/keep", placement: "max.ru/join/Keep" },
        { key: "max.ru/join/other", placement: "max.ru/join/Other" },
      ], channelCount: 2 },
      { campaignId: "202", channels: [
        { key: "max.ru/join/keep", placement: "max.ru/join/Keep" },
      ], channelCount: 1 },
    ],
    totalChannels: 3,
  };
  const filtered = filterProtectedChannels(report, ["max.ru/join/Keep"]);

  assert.equal(filtered.totalChannels, 1);
  assert.deepEqual(filtered.campaigns.map((campaign) => campaign.channelCount), [1, 0]);
  assert.equal(report.totalChannels, 3);
});

test("serializes exclusion edits and preserves them when saving other settings", async () => {
  const settingsPath = path.join(settingsTestDirectory, "settings.json");
  const baseSettings = {
    costThreshold: 5,
    maxCostThreshold: 240,
    periodDays: 21,
    prefixes: ["max.ru/"],
    includeApps: true,
  };

  await Promise.all([
    addProtectedPlacement("max.ru/join/Keep"),
    saveChannelSettings(baseSettings),
    addProtectedPlacement("com.example.game"),
  ]);
  let saved = normalizeChannelSettings(
    JSON.parse(await fs.readFile(settingsPath, "utf8")),
  );

  assert.equal(saved.costThreshold, 5);
  assert.deepEqual(saved.protectedPlacements, [
    "max.ru/join/Keep",
    "com.example.game",
  ]);

  await removeProtectedPlacement("MAX.ru/join/keep");
  saved = normalizeChannelSettings(
    JSON.parse(await fs.readFile(settingsPath, "utf8")),
  );
  assert.deepEqual(saved.protectedPlacements, ["com.example.game"]);
});

test("requires the upper threshold to be greater than the lower threshold", () => {
  assert.throws(
    () => normalizeChannelSettings({
      costThreshold: 20,
      maxCostThreshold: 20,
      periodDays: 30,
      prefixes: [],
    }),
    /больше нижнего/,
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

test("keeps app checks disabled for existing settings", () => {
  assert.equal(
    normalizeChannelSettings({
      costThreshold: 15,
      periodDays: 30,
      prefixes: ["t.me/"],
    }).includeApps,
    false,
  );
});

test("recognizes app placements only when app checks are enabled", () => {
  const enabledSettings = normalizeChannelSettings({
    costThreshold: 15,
    periodDays: 30,
    prefixes: [],
    includeApps: true,
  });
  const disabledSettings = { ...enabledSettings, includeApps: false };

  assert.equal(normalizeAppPlacement("com.example.game")?.kind, "app");
  assert.equal(normalizeTrackedPlacement("dsp-network.example", enabledSettings)?.kind, "app");
  assert.equal(
    normalizeTrackedPlacement("arrows.maze.escape.out.puzzle.ru", enabledSettings)?.kind,
    "app",
  );
  assert.equal(normalizeTrackedPlacement("com.example.game", disabledSettings), null);
  assert.equal(normalizeTrackedPlacement("ordinary-site.ru", enabledSettings), null);
});

test("includes costly unblocked apps in the channel report when enabled", () => {
  const settings = normalizeChannelSettings({
    costThreshold: 15,
    periodDays: 30,
    prefixes: ["t.me/"],
    includeApps: true,
  });
  const campaigns = [{
    campaignId: "101",
    blockedSites: ["com.example.blocked"],
  }];
  const report = [
    "101\tcom.example.game\t20.00",
    "101\tcom.example.game\t2.50",
    "101\tcom.example.blocked\t100.00",
    "101\tdsp-network.example\t15.00",
    "101\tt.me/channel\t16.00",
    "101\tordinary-site.ru\t500.00",
  ].join("\n");
  const parsed = parseChannelPerformanceReport(report, campaigns, settings);

  assert.deepEqual(
    parsed.get("101").map(({ placement, cost, kind }) => ({ placement, cost, kind })),
    [
      { placement: "com.example.game", cost: 22.5, kind: "app" },
      { placement: "t.me/channel", cost: 16, kind: "channel" },
    ],
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
