import assert from "node:assert/strict";
import test from "node:test";

process.env.BM_BLOCKED_DISABLE_SERVER = "1";

const {
  buildChannelReportDefinition,
  getLastDaysRange,
  getLast30DaysRange,
  normalizeChannelPlacement,
  normalizeChannelSettings,
  parseChannelPerformanceReport,
  selectChannelsForAvailableSlots,
} = await import("./server.js");

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

test("uses a custom threshold and custom channel prefixes", () => {
  const settings = normalizeChannelSettings({
    costThreshold: 25.5,
    periodDays: 14,
    prefixes: ["example.ru/channels/", "t.me/"],
  });
  const campaigns = [{ campaignId: "101", blockedSites: [] }];
  const report = [
    "101\texample.ru/channels/working\t25.51",
    "101\texample.ru/other\t100.00",
    "101\tt.me/exact-threshold\t25.50",
  ].join("\n");
  const parsed = parseChannelPerformanceReport(report, campaigns, settings);

  assert.deepEqual(
    parsed.get("101").map((channel) => channel.placement),
    ["example.ru/channels/working"],
  );
});
