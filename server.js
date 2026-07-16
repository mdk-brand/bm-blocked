import http from "node:http";
import crypto from "node:crypto";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { getAsset, isSea } from "node:sea";
import { fileURLToPath } from "node:url";

const isPortableExecutable = isSea();
const shutdownToken = process.env.BM_BLOCKED_SHUTDOWN_TOKEN || "";
const parentProcessId = Number(process.env.BM_BLOCKED_PARENT_PID) || 0;
const notificationPipeName = process.env.BM_BLOCKED_NOTIFICATION_PIPE || "";
const internalToken = process.env.BM_BLOCKED_INTERNAL_TOKEN || "";
const root = isPortableExecutable
  ? path.dirname(process.execPath)
  : path.dirname(fileURLToPath(import.meta.url));
const port = 8124;
const host = "127.0.0.1";
const directApiBaseUrl = "https://api.direct.yandex.com/json/v5";
const directApiUnifiedBaseUrl = "https://api.direct.yandex.com/json/v501";
const pageLimit = 10000;
const siteCheckConcurrency = 8;
const siteCheckTimeoutMs = 8000;
const authConfigPath = path.join(root, "auth-config.json");
const authCookieName = "bm_blocked_session";
const authSessionDurationSeconds = 12 * 60 * 60;
const authLoginWindowMs = 15 * 60 * 1000;
const authMaxLoginAttempts = 5;
const authLoginAttempts = new Map();
let updateState = {
  available: false,
  tag: "",
  name: "",
  notes: "",
  showReleaseNotes: false,
  revision: 0,
};
const authRuntimeSessionSecret = crypto.randomBytes(32);
const authConfig = await loadAuthConfig();
const checkedWebsiteZones = new Set([
  "ru",
  "info",
  "tv",
  "media",
  "com",
  "net",
  "org",
  "by",
  "bz",
  "biz",
  "fm",
]);
const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

class InputError extends Error {
  constructor(message) {
    super(message);
    this.statusCode = 400;
  }
}

async function loadAuthConfig() {
  try {
    const rawConfig = await fs.readFile(authConfigPath, "utf8");
    const config = JSON.parse(rawConfig);
    const readCredential = (name) => {
      const credential = config[name] || {};
      const iterations = Number(credential.iterations);
      const salt = Buffer.from(String(credential.salt || ""), "base64");
      const hash = Buffer.from(String(credential.hash || ""), "base64");

      if (
        credential.algorithm !== "pbkdf2-sha256" ||
        !Number.isInteger(iterations) ||
        iterations < 100000 ||
        salt.length < 16 ||
        hash.length < 32
      ) {
        throw new Error(`Некорректные параметры защиты: ${name}.`);
      }

      return { iterations, salt, hash };
    };

    if (config.version !== 2) {
      throw new Error("Конфигурацию авторизации нужно создать заново.");
    }

    return {
      username: readCredential("username"),
      password: readCredential("password"),
    };
  } catch (error) {
    if (error.code === "ENOENT") {
      console.warn("Authorization is not configured: auth-config.json is missing.");
    } else {
      console.error(`Authorization configuration error: ${error.message}`);
    }

    return null;
  }
}

function sendJson(res, statusCode, payload, headers = {}) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...headers,
  });
  res.end(JSON.stringify(payload));
}

async function readJson(req) {
  const chunks = [];
  let totalBytes = 0;

  for await (const chunk of req) {
    totalBytes += chunk.length;

    if (totalBytes > 16 * 1024 * 1024) {
      throw new InputError("Тело запроса слишком большое.");
    }

    chunks.push(chunk);
  }

  const rawBody = Buffer.concat(chunks).toString("utf8");
  return rawBody ? JSON.parse(rawBody) : {};
}

function timingSafeStringEqual(left, right) {
  const leftDigest = crypto.createHash("sha256").update(String(left)).digest();
  const rightDigest = crypto.createHash("sha256").update(String(right)).digest();
  return crypto.timingSafeEqual(leftDigest, rightDigest);
}

function deriveCredentialHash(value, credential) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(
      String(value),
      credential.salt,
      credential.iterations,
      credential.hash.length,
      "sha256",
      (error, derivedKey) => {
        if (error) {
          reject(error);
          return;
        }

        resolve(derivedKey);
      },
    );
  });
}

function parseCookies(req) {
  return String(req.headers.cookie || "")
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce((cookies, part) => {
      const separatorIndex = part.indexOf("=");

      if (separatorIndex > 0) {
        cookies[part.slice(0, separatorIndex)] = decodeURIComponent(
          part.slice(separatorIndex + 1),
        );
      }

      return cookies;
    }, {});
}

function createSessionToken() {
  const payload = Buffer.from(
    JSON.stringify({
      sessionId: crypto.randomBytes(16).toString("base64url"),
      expiresAt: Date.now() + authSessionDurationSeconds * 1000,
    }),
  ).toString("base64url");
  const signature = crypto
    .createHmac("sha256", authRuntimeSessionSecret)
    .update(payload)
    .digest("base64url");

  return `${payload}.${signature}`;
}

function readSession(req) {
  if (!authConfig) {
    return null;
  }

  const token = parseCookies(req)[authCookieName];

  if (!token) {
    return null;
  }

  const [payload, signature, extraPart] = token.split(".");

  if (!payload || !signature || extraPart) {
    return null;
  }

  const expectedSignature = crypto
    .createHmac("sha256", authRuntimeSessionSecret)
    .update(payload)
    .digest("base64url");

  if (!timingSafeStringEqual(signature, expectedSignature)) {
    return null;
  }

  try {
    const session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));

    if (
      typeof session.sessionId !== "string" ||
      session.sessionId.length < 16 ||
      !Number.isFinite(session.expiresAt) ||
      session.expiresAt <= Date.now()
    ) {
      return null;
    }

    return session;
  } catch (error) {
    return null;
  }
}

function getLoginAttemptKey(req) {
  return req.socket.remoteAddress || "local";
}

function getActiveLoginAttempt(req) {
  const key = getLoginAttemptKey(req);
  const attempt = authLoginAttempts.get(key);

  if (attempt && attempt.resetAt <= Date.now()) {
    authLoginAttempts.delete(key);
    return null;
  }

  return attempt || null;
}

function registerFailedLogin(req) {
  const key = getLoginAttemptKey(req);
  const currentAttempt = getActiveLoginAttempt(req);
  const attempt = currentAttempt || {
    count: 0,
    resetAt: Date.now() + authLoginWindowMs,
  };

  attempt.count += 1;
  authLoginAttempts.set(key, attempt);
  return attempt;
}

async function handleAuthLoginApi(req, res) {
  if (!authConfig) {
    sendJson(res, 503, {
      error: "Авторизация не настроена. Запустите set-auth.ps1 на основном компьютере.",
      configured: false,
    });
    return;
  }

  const activeAttempt = getActiveLoginAttempt(req);

  if (activeAttempt?.count >= authMaxLoginAttempts) {
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil((activeAttempt.resetAt - Date.now()) / 1000),
    );
    sendJson(
      res,
      429,
      {
        error: "Слишком много попыток входа. Попробуйте позже.",
        retryAfterSeconds,
      },
      { "Retry-After": String(retryAfterSeconds) },
    );
    return;
  }

  try {
    const payload = await readJson(req);
    const username = String(payload.username || "").trim();
    const password = String(payload.password || "");
    const [derivedUsernameHash, derivedPasswordHash] = await Promise.all([
      deriveCredentialHash(username, authConfig.username),
      deriveCredentialHash(password, authConfig.password),
    ]);
    const usernameMatches = crypto.timingSafeEqual(
      derivedUsernameHash,
      authConfig.username.hash,
    );
    const passwordMatches = crypto.timingSafeEqual(
      derivedPasswordHash,
      authConfig.password.hash,
    );

    if (!usernameMatches || !passwordMatches) {
      const attempt = registerFailedLogin(req);
      const isBlocked = attempt.count >= authMaxLoginAttempts;
      sendJson(res, isBlocked ? 429 : 401, {
        error: isBlocked
          ? "Слишком много попыток входа. Попробуйте через 15 минут."
          : "Неверный логин или пароль.",
      });
      return;
    }

    authLoginAttempts.delete(getLoginAttemptKey(req));
    const sessionToken = createSessionToken();
    sendJson(
      res,
      200,
      { authenticated: true, username: "Сотрудник" },
      {
        "Set-Cookie": `${authCookieName}=${encodeURIComponent(sessionToken)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${authSessionDurationSeconds}`,
      },
    );
  } catch (error) {
    sendJson(res, 400, { error: "Не удалось обработать данные для входа." });
  }
}

function handleAuthStatusApi(req, res) {
  const session = readSession(req);
  sendJson(res, 200, {
    configured: Boolean(authConfig),
    authenticated: Boolean(session),
    username: session ? "Сотрудник" : "",
  });
}

function handleAuthLogoutApi(req, res) {
  sendJson(
    res,
    200,
    { authenticated: false },
    {
      "Set-Cookie": `${authCookieName}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
    },
  );
}

function directHeaders(token, clientLogin = "") {
  const headers = {
    Authorization: `Bearer ${token}`,
    "Accept-Language": "ru",
    "Content-Type": "application/json; charset=utf-8",
  };

  if (clientLogin) {
    headers["Client-Login"] = clientLogin;
  }

  return headers;
}

function parseDirectError(payload) {
  const apiError = payload.error || {};
  return apiError.error_detail || apiError.error_string || "Ошибка API Яндекс Директа.";
}

async function directRequest(token, pathName, body, options = {}) {
  let response;

  try {
    response = await fetch(`${options.apiBaseUrl || directApiBaseUrl}/${pathName}`, {
      method: "POST",
      headers: directHeaders(token, options.clientLogin),
      body: JSON.stringify(body),
    });
  } catch (error) {
    const technicalReason = [error.message, error.cause?.code].filter(Boolean).join(", ");
    throw new Error(
      `Не удалось подключиться к API Яндекс Директа. Проверьте интернет, VPN/прокси и доступ к api.direct.yandex.com. Технически: ${technicalReason}`,
    );
  }

  const responseText = await response.text();
  let payload;

  try {
    payload = JSON.parse(responseText);
  } catch (error) {
    throw new Error(`API вернул не JSON: ${responseText.slice(0, 120)}`);
  }

  if (!response.ok || payload.error) {
    throw new Error(parseDirectError(payload));
  }

  return payload.result || {};
}

function requireString(payload, key, label = key) {
  const value = String(payload[key] || "").trim();

  if (!value) {
    throw new InputError(`Не заполнено поле: ${label}.`);
  }

  return value;
}

function formatClientName(client) {
  const login = client.Login || "";
  const id = client.ClientId ? String(client.ClientId) : "";
  const info = client.ClientInfo;
  const infoText =
    typeof info === "string"
      ? info
      : info && typeof info === "object"
        ? Object.values(info).filter(Boolean).join(" ")
        : "";
  const baseName = infoText || login || id;

  return login && infoText ? `${infoText} (${login})` : baseName;
}

async function loadDirectClients(token) {
  try {
    const result = await directRequest(token, "agencyclients", {
      method: "get",
      params: {
        SelectionCriteria: {},
        FieldNames: ["ClientId", "Login", "ClientInfo"],
      },
    });
    const clients = normalizeClients(result.Clients);

    if (clients.length > 0) {
      return clients;
    }
  } catch (error) {
    // Ordinary advertiser tokens do not have AgencyClients access.
  }

  const result = await directRequest(token, "clients", {
    method: "get",
    params: {
      FieldNames: ["ClientId", "Login", "ClientInfo"],
    },
  });

  return normalizeClients(result.Clients);
}

function normalizeClients(clients = []) {
  return clients
    .map((client) => ({
      id: client.ClientId ? String(client.ClientId) : "",
      login: client.Login || "",
      name: formatClientName(client),
    }))
    .filter((client) => client.login || client.id || client.name)
    .sort((left, right) => left.name.localeCompare(right.name, "ru"));
}

function getExcludedSites(campaign) {
  const items = campaign.ExcludedSites?.Items;
  return Array.isArray(items) ? items.filter(Boolean) : [];
}

function strategyUsesNetwork(strategy) {
  const networkType = strategy?.Network?.BiddingStrategyType;
  return Boolean(networkType && !["SERVING_OFF", "UNKNOWN"].includes(networkType));
}

function packageStrategyUsesNetwork(packageStrategy) {
  return packageStrategy?.Platforms?.Network === "YES";
}

function campaignUsesNetwork(campaign) {
  if (campaign.Type === "TEXT_CAMPAIGN") {
    return (
      strategyUsesNetwork(campaign.TextCampaign?.BiddingStrategy) ||
      packageStrategyUsesNetwork(campaign.TextCampaign?.PackageBiddingStrategy)
    );
  }

  if (campaign.Type === "UNIFIED_CAMPAIGN") {
    return (
      strategyUsesNetwork(campaign.UnifiedCampaign?.BiddingStrategy) ||
      packageStrategyUsesNetwork(campaign.UnifiedCampaign?.PackageBiddingStrategy)
    );
  }

  return false;
}

function campaignIsActive(campaign) {
  return campaign.State === "ON";
}

function toPublicCampaign(campaign) {
  return {
    campaignId: campaign.campaignId,
    campaignName: campaign.campaignName,
    blockedCount: campaign.blockedCount,
    state: campaign.state,
    status: campaign.status,
  };
}

async function loadBlockedPlacementsReport(token, clientLogin) {
  const campaigns = [];
  let offset = 0;

  while (true) {
    const result = await directRequest(
      token,
      "campaigns",
      {
        method: "get",
        params: {
          SelectionCriteria: {
            Types: ["TEXT_CAMPAIGN", "UNIFIED_CAMPAIGN"],
            States: ["ON"],
          },
          FieldNames: ["Id", "Name", "Type", "State", "Status", "ExcludedSites"],
          TextCampaignFieldNames: ["BiddingStrategy", "PackageBiddingStrategy"],
          UnifiedCampaignFieldNames: ["BiddingStrategy", "PackageBiddingStrategy"],
          Page: {
            Limit: pageLimit,
            Offset: offset,
          },
        },
      },
      { clientLogin },
    );

    campaigns.push(...(result.Campaigns || []));

    if (!result.LimitedBy) {
      break;
    }

    offset = Number(result.LimitedBy);
  }

  return campaigns
    .filter(campaignIsActive)
    .filter(campaignUsesNetwork)
    .map((campaign) => {
      const blockedSites = getExcludedSites(campaign);

      return {
        campaignId: String(campaign.Id),
        campaignName: campaign.Name || String(campaign.Id),
        campaignType: campaign.Type,
        blockedCount: blockedSites.length,
        blockedSites,
        state: campaign.State || "",
        status: campaign.Status || "",
      };
    })
    .sort((left, right) => right.blockedCount - left.blockedCount || left.campaignName.localeCompare(right.campaignName, "ru"));
}

function looksLikeMobileAppHostname(value) {
  const hostname = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/^www\./, "")
    .replace(/\.$/, "");
  const labels = hostname.split(".").filter(Boolean);
  const packageLabels = checkedWebsiteZones.has(labels.at(-1))
    ? labels.slice(0, -1)
    : labels;

  if (hostname.startsWith("dsp-") || hostname.startsWith("dsp.")) {
    return true;
  }

  if (
    (packageLabels[0] === "com" || packageLabels[0] === "io") &&
    packageLabels.length >= 3
  ) {
    return true;
  }

  return packageLabels.length >= 5 &&
    packageLabels.every((label) => /^[a-z][a-z0-9_]*$/.test(label));
}

function isCheckedWebsiteHostname(value) {
  const hostname = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/^www\./, "")
    .replace(/\.$/, "");
  const labels = hostname.split(".").filter(Boolean);

  return !looksLikeMobileAppHostname(hostname) &&
    labels.length >= 2 &&
    checkedWebsiteZones.has(labels.at(-1));
}

function normalizePlacementValue(value) {
  return String(value || "")
    .trim()
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .replace(/\u00A0/g, " ")
    .trim()
    .replace(/^<|>$/g, "")
    .replace(/^\[|\]$/g, "")
    .replace(/^["'`]+|["'`]+$/g, "")
    .trim();
}

function getPlacementCheckUrls(value) {
  let rawValue = normalizePlacementValue(value);
  const embeddedUrl = rawValue.match(/https?:\/\/[^\s<>"'`)\]]+/i);

  if (embeddedUrl) {
    rawValue = embeddedUrl[0];
  }

  if (!rawValue) {
    return { type: "invalid", urls: [] };
  }

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(rawValue)) {
    try {
      const url = new URL(rawValue);

      if (url.protocol !== "http:" && url.protocol !== "https:") {
        return { type: "invalid", urls: [] };
      }

      if (!isCheckedWebsiteHostname(url.hostname)) {
        return looksLikeMobileAppHostname(url.hostname)
          ? { type: "app", urls: [] }
          : { type: "ignored", urls: [] };
      }

      url.hash = "";
      const alternateUrl = new URL(url.href);
      alternateUrl.protocol = url.protocol === "https:" ? "http:" : "https:";

      return {
        type: "web",
        urls: Array.from(new Set([url.href, alternateUrl.href])),
      };
    } catch (error) {
      return { type: "invalid", urls: [] };
    }
  }

  if (/\s/.test(rawValue)) {
    return { type: "invalid", urls: [] };
  }

  let hostname;

  try {
    hostname = new URL(`https://${rawValue.replace(/^\/+/, "")}`).hostname;
  } catch (error) {
    return { type: "invalid", urls: [] };
  }

  if (!isCheckedWebsiteHostname(hostname)) {
    return looksLikeMobileAppHostname(hostname)
      ? { type: "app", urls: [] }
      : { type: "ignored", urls: [] };
  }

  return {
    type: "web",
    urls: [`https://${rawValue.replace(/^\/+/, "")}`, `http://${rawValue.replace(/^\/+/, "")}`],
  };
}

function getRootDomain(value) {
  try {
    const labels = new URL(value).hostname
      .toLowerCase()
      .replace(/^www\./, "")
      .replace(/\.$/, "")
      .split(".")
      .filter(Boolean);

    return labels.slice(-2).join(".");
  } catch (error) {
    return "";
  }
}

function isSuspiciousRedirect(sourceUrl, finalUrl) {
  try {
    if (getRootDomain(sourceUrl) === getRootDomain(finalUrl)) {
      return false;
    }

    const trackingParameters = new Set([
      "aff",
      "aff_id",
      "affiliate",
      "affiliate_id",
      "click_id",
      "clickid",
      "erid",
      "marker",
      "subid",
    ]);
    const finalSearchParameters = new URL(finalUrl).searchParams;

    return [...finalSearchParameters.keys()].some((key) =>
      trackingParameters.has(key.toLowerCase()),
    );
  } catch (error) {
    return false;
  }
}

async function probeUrl(url, method = "GET") {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), siteCheckTimeoutMs);

  try {
    const response = await fetch(url, {
      method,
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru,en;q=0.9",
        "Cache-Control": "no-cache",
      },
    });
    clearTimeout(timeout);
    const preview = method === "HEAD" ? "" : await readResponsePreview(response);
    const errorPage = looksLikeHttpErrorPage(preview);
    const suspiciousRedirect = isSuspiciousRedirect(url, response.url);
    const unavailableStatus =
      response.status === 404 ||
      response.status === 410 ||
      response.status >= 500;

    return {
      ok: !unavailableStatus && !errorPage && !suspiciousRedirect,
      statusCode: response.status,
      finalUrl: response.url,
      error: errorPage
        ? "http_error_page"
        : suspiciousRedirect
          ? "suspicious_redirect"
          : undefined,
    };
  } catch (error) {
    return {
      ok: false,
      error: error.name === "AbortError" ? "timeout" : error.message,
    };
  } finally {
    clearTimeout(timeout);
  }
}

function canReachUrlHost(value) {
  try {
    const url = new URL(value);
    const port = url.port || (url.protocol === "https:" ? 443 : 80);

    return new Promise((resolve) => {
      const socket = net.createConnection({
        host: url.hostname,
        port,
      });
      let settled = false;

      const finish = (isReachable) => {
        if (settled) {
          return;
        }

        settled = true;
        socket.destroy();
        resolve(isReachable);
      };

      socket.setTimeout(2500, () => finish(false));
      socket.once("connect", () => finish(true));
      socket.once("error", () => finish(false));
    });
  } catch (error) {
    return Promise.resolve(false);
  }
}

async function readResponsePreview(response) {
  if (!response.body) {
    return "";
  }

  const contentType = response.headers.get("content-type") || "";

  if (!/text|html|xml|json/i.test(contentType)) {
    await response.body.cancel();
    return "";
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let preview = "";
  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    reader.cancel().catch(() => {});
  }, 1500);

  try {
    while (!timedOut && preview.length < 12000) {
      const { done, value } = await reader.read().catch((error) => {
        if (timedOut) {
          return { done: true };
        }

        throw error;
      });

      if (done) {
        break;
      }

      preview += decoder.decode(value, { stream: true });
    }
  } finally {
    clearTimeout(timeout);
    await reader.cancel().catch(() => {});
  }

  return preview;
}

function looksLikeHttpErrorPage(value) {
  const text = String(value || "").toLowerCase();
  const compactText = text.replace(/\s+/g, " ");
  const errorPatterns = [
    "http error 404",
    "http error 410",
    "http error 500",
    "http error 502",
    "http error 503",
    "http error 504",
    "404 not found",
    "410 gone",
    "500 internal server error",
    "502 bad gateway",
    "503 service unavailable",
    "504 gateway timeout",
    "this site can't be reached",
    "this site can’t be reached",
    "server ip address could not be found",
    "err_name_not_resolved",
    "err_connection_timed_out",
    "err_connection_refused",
    "err_connection_reset",
    "err_address_unreachable",
    "site can’t be reached",
    "site can't be reached",
    "page not found",
    "страница не найдена",
    "сайт недоступен",
  ];

  return errorPatterns.some((pattern) => compactText.includes(pattern));
}

async function checkPlacement(placement) {
  const checkTarget = getPlacementCheckUrls(placement);

  if (checkTarget.type !== "web") {
    return {
      placement,
      type: checkTarget.type,
      isUnavailable: false,
      checked: false,
    };
  }

  let lastProbe = null;
  const probes = [];

  for (const url of checkTarget.urls) {
    lastProbe = await probeUrl(url);
    probes.push(lastProbe);

    if (lastProbe.ok) {
      return {
        placement,
        type: "web",
        isUnavailable: false,
        checked: true,
        statusCode: lastProbe.statusCode,
        finalUrl: lastProbe.finalUrl,
      };
    }
  }

  const isTransportFailure = (probe) =>
    !probe?.statusCode &&
    (probe?.error === "fetch failed" || probe?.error === "timeout");

  if (probes.every(isTransportFailure)) {
    for (const url of checkTarget.urls) {
      lastProbe = await probeUrl(url, "HEAD");
      probes.push(lastProbe);

      if (lastProbe.ok) {
        return {
          placement,
          type: "web",
          isUnavailable: false,
          checked: true,
          statusCode: lastProbe.statusCode,
          finalUrl: lastProbe.finalUrl,
        };
      }
    }
  }

  if (probes.every(isTransportFailure)) {
    for (const url of checkTarget.urls) {
      if (await canReachUrlHost(url)) {
        return {
          placement,
          type: "web",
          isUnavailable: false,
          checked: true,
          connectionOnly: true,
        };
      }
    }
  }

  const definitiveProbe = [...probes].reverse().find((probe) =>
    !isTransportFailure(probe),
  );
  lastProbe = definitiveProbe || lastProbe;

  return {
    placement,
    type: "web",
    isUnavailable: true,
    checked: true,
    url: checkTarget.urls[0],
    statusCode: lastProbe?.statusCode,
    error: lastProbe?.error || "unavailable",
  };
}

async function mapWithConcurrency(items, limit, mapper) {
  const results = new Array(items.length);
  let nextIndex = 0;

  async function worker() {
    while (nextIndex < items.length) {
      const currentIndex = nextIndex;
      nextIndex += 1;
      results[currentIndex] = await mapper(items[currentIndex], currentIndex);
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, () => worker()),
  );

  return results;
}

async function checkBlockedPlacementsReport(token, clientLogin, campaignIds = []) {
  const campaigns = await loadBlockedPlacementsReport(token, clientLogin);
  const selectedCampaignIds = new Set(campaignIds.map((campaignId) => String(campaignId)));
  const campaignsToCheck =
    selectedCampaignIds.size > 0
      ? campaigns.filter((campaign) => selectedCampaignIds.has(campaign.campaignId))
      : campaigns;
  const uniquePlacements = Array.from(
    new Set(campaignsToCheck.flatMap((campaign) => campaign.blockedSites)),
  );
  const checks = await mapWithConcurrency(uniquePlacements, siteCheckConcurrency, checkPlacement);
  const checksByPlacement = new Map(checks.map((check) => [check.placement, check]));
  const checkedCampaigns = campaignsToCheck.map((campaign) => {
    const campaignChecks = campaign.blockedSites.map((placement) => checksByPlacement.get(placement));
    const unavailableCount = campaignChecks.filter((check) => check?.isUnavailable).length;
    const unavailableSites = campaignChecks
      .filter((check) => check?.isUnavailable)
      .map((check) => ({
        placement: check.placement,
        url: check.url,
        type: check.type,
        statusCode: check.statusCode,
        error: check.error,
      }));
    const unavailableWebCount = unavailableSites.filter((site) => site.type === "web").length;
    const checkedWebCount = campaignChecks.filter((check) => check?.type === "web" && check?.checked).length;
    const skippedAppCount = campaignChecks.filter((check) => check?.type === "app" && !check?.checked).length;

    return {
      ...toPublicCampaign(campaign),
      unavailableCount,
      unavailableWebCount,
      unavailableSites,
      checkedWebCount,
      skippedAppCount,
    };
  });

  return {
    campaigns: checkedCampaigns,
    totalCampaigns: checkedCampaigns.length,
    totalBlockedSites: checkedCampaigns.reduce((sum, campaign) => sum + campaign.blockedCount, 0),
    totalUnavailableSites: checkedCampaigns.reduce((sum, campaign) => sum + campaign.unavailableCount, 0),
    totalUnavailableWebSites: checkedCampaigns.reduce(
      (sum, campaign) => sum + campaign.unavailableWebCount,
      0,
    ),
    checkedWebSites: checks.filter((check) => check.type === "web" && check.checked).length,
    skippedAppSites: checks.filter((check) => check.type === "app" && !check.checked).length,
  };
}

function splitIntoChunks(items, size) {
  const chunks = [];

  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size));
  }

  return chunks;
}

function formatDirectNotifications(notifications = []) {
  return notifications
    .map((notification) =>
      [notification.Message, notification.Details].filter(Boolean).join(": "),
    )
    .join("; ");
}

async function clearUnavailablePlacements(token, clientLogin, selections = []) {
  const campaigns = await loadBlockedPlacementsReport(token, clientLogin);
  const campaignsById = new Map(
    campaigns.map((campaign) => [campaign.campaignId, campaign]),
  );
  const updates = [];
  const failedCampaigns = [];

  for (const selection of selections) {
    const campaignId = String(selection?.campaignId || "").trim();
    const campaign = campaignsById.get(campaignId);
    const unavailablePlacements = Array.isArray(selection?.unavailablePlacements)
      ? selection.unavailablePlacements.map((placement) => String(placement))
      : [];

    if (!campaign) {
      failedCampaigns.push({
        campaignId,
        error: "Активная кампания РСЯ не найдена.",
      });
      continue;
    }

    const unavailableSet = new Set(unavailablePlacements);
    const remainingSites = campaign.blockedSites.filter(
      (placement) => !unavailableSet.has(placement),
    );
    const removedCount = campaign.blockedSites.length - remainingSites.length;

    if (removedCount === 0) {
      continue;
    }

    updates.push({
      campaignId,
      campaignName: campaign.campaignName,
      campaignType: campaign.campaignType,
      removedCount,
      remainingSites,
    });
  }

  const updatedCampaigns = [];
  const updateGroups = [
    {
      items: updates.filter((update) => update.campaignType === "TEXT_CAMPAIGN"),
      apiBaseUrl: directApiBaseUrl,
    },
    {
      items: updates.filter((update) => update.campaignType === "UNIFIED_CAMPAIGN"),
      apiBaseUrl: directApiUnifiedBaseUrl,
    },
  ];

  for (const group of updateGroups) {
    for (const chunk of splitIntoChunks(group.items, 10)) {
      let result;

      try {
        result = await directRequest(
          token,
          "campaigns",
          {
            method: "update",
            params: {
              Campaigns: chunk.map((update) => ({
                Id: Number(update.campaignId),
                ExcludedSites: {
                  Items: update.remainingSites,
                },
              })),
            },
          },
          {
            clientLogin,
            apiBaseUrl: group.apiBaseUrl,
          },
        );
      } catch (error) {
        failedCampaigns.push(
          ...chunk.map((update) => ({
            campaignId: update.campaignId,
            error: error.message,
          })),
        );
        continue;
      }

      const updateResults = result.UpdateResults || [];

      chunk.forEach((update, index) => {
        const updateResult = updateResults[index] || {};

        if (Array.isArray(updateResult.Errors) && updateResult.Errors.length > 0) {
          failedCampaigns.push({
            campaignId: update.campaignId,
            error: formatDirectNotifications(updateResult.Errors),
          });
          return;
        }

        if (!updateResult.Id) {
          failedCampaigns.push({
            campaignId: update.campaignId,
            error: "Яндекс Директ не подтвердил изменение кампании.",
          });
          return;
        }

        updatedCampaigns.push({
          campaignId: update.campaignId,
          removedCount: update.removedCount,
          blockedCount: update.remainingSites.length,
        });
      });
    }
  }

  return {
    updatedCampaigns,
    failedCampaigns,
    totalRemoved: updatedCampaigns.reduce(
      (sum, campaign) => sum + campaign.removedCount,
      0,
    ),
  };
}

async function handleDirectClientsApi(req, res) {
  try {
    const payload = await readJson(req);
    const token = requireString(payload, "token", "OAuth-токен");
    const clients = await loadDirectClients(token);

    sendJson(res, 200, { clients });
  } catch (error) {
    sendJson(res, error.statusCode || 502, { error: error.message });
  }
}

async function handleBlockedPlacementsApi(req, res) {
  try {
    const payload = await readJson(req);
    const token = requireString(payload, "token", "OAuth-токен");
    const clientLogin = requireString(payload, "clientLogin", "клиент");
    const campaigns = await loadBlockedPlacementsReport(token, clientLogin);
    const publicCampaigns = campaigns.map(toPublicCampaign);

    sendJson(res, 200, {
      campaigns: publicCampaigns,
      totalCampaigns: publicCampaigns.length,
      totalBlockedSites: publicCampaigns.reduce((sum, campaign) => sum + campaign.blockedCount, 0),
    });
  } catch (error) {
    sendJson(res, error.statusCode || 502, { error: error.message });
  }
}

async function handleCheckPlacementsApi(req, res) {
  try {
    const payload = await readJson(req);
    const token = requireString(payload, "token", "OAuth-токен");
    const clientLogin = requireString(payload, "clientLogin", "клиент");
    const campaignIds = Array.isArray(payload.campaignIds) ? payload.campaignIds : [];
    const report = await checkBlockedPlacementsReport(token, clientLogin, campaignIds);

    sendJson(res, 200, report);
  } catch (error) {
    sendJson(res, error.statusCode || 502, { error: error.message });
  }
}

async function sendTrayMessage(payload) {
  if (process.platform !== "win32" || !notificationPipeName) {
    return false;
  }

  const pipePath = `\\\\.\\pipe\\${notificationPipeName}`;

  return new Promise((resolve) => {
    let settled = false;
    const socket = net.createConnection(pipePath);
    const finish = (delivered) => {
      if (settled) {
        return;
      }

      settled = true;
      socket.destroy();
      resolve(delivered);
    };

    socket.setTimeout(1500);
    socket.once("connect", () => {
      socket.end(`${JSON.stringify(payload)}\n`, () => finish(true));
    });
    socket.once("error", () => finish(false));
    socket.once("timeout", () => finish(false));
  });
}

async function sendDesktopNotification(message) {
  return sendTrayMessage({ type: "check-completion", message });
}

async function handleDesktopNotificationApi(req, res) {
  try {
    const payload = await readJson(req);
    let message;

    if (payload.kind === "success") {
      const campaignCount = Math.max(0, Math.trunc(Number(payload.campaignCount) || 0));
      message = `Проверка завершена. Проверено кампаний: ${campaignCount}.`;
    } else if (payload.kind === "error") {
      const errorMessage = String(payload.error || "неизвестная ошибка")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 300);
      message = `Проверка завершилась ошибкой: ${errorMessage}`;
    } else {
      throw new InputError("Неизвестный тип системного уведомления.");
    }

    const delivered = await sendDesktopNotification(message);
    sendJson(res, 200, { delivered });
  } catch (error) {
    sendJson(res, error.statusCode || 500, { error: error.message });
  }
}

async function handleInternalUpdateStateApi(req, res) {
  try {
    const payload = await readJson(req);

    if (payload.action === "clear") {
      updateState = {
        available: false,
        tag: "",
        name: "",
        notes: "",
        showReleaseNotes: false,
        revision: updateState.revision + 1,
      };
    } else if (payload.action === "available") {
      updateState = {
        available: true,
        tag: String(payload.tag || "").trim().slice(0, 64),
        name: String(payload.name || payload.tag || "").trim().slice(0, 200),
        notes: String(payload.notes || "").slice(0, 100000),
        showReleaseNotes: payload.showReleaseNotes === true,
        revision: updateState.revision + 1,
      };
    } else {
      throw new InputError("Неизвестное действие внутреннего API обновлений.");
    }

    sendJson(res, 200, { updated: true });
  } catch (error) {
    sendJson(res, error.statusCode || 500, { error: error.message });
  }
}

function handleUpdateStatusApi(req, res) {
  sendJson(res, 200, updateState);
}

async function handleUpdateActionApi(req, res) {
  try {
    const payload = await readJson(req);
    const action = String(payload.action || "").trim().toLowerCase();

    if (action !== "install" && action !== "later") {
      throw new InputError("Неизвестное действие обновления.");
    }

    const delivered = await sendTrayMessage({ type: "update-action", action });

    if (!delivered) {
      sendJson(res, 503, { error: "bm-blocked.exe не принял команду обновления." });
      return;
    }

    updateState = {
      ...updateState,
      showReleaseNotes: false,
      revision: updateState.revision + 1,
    };
    sendJson(res, 200, { delivered: true });
  } catch (error) {
    sendJson(res, error.statusCode || 500, { error: error.message });
  }
}

async function handleClearPlacementsApi(req, res) {
  try {
    const payload = await readJson(req);
    const token = requireString(payload, "token", "OAuth-токен");
    const clientLogin = requireString(payload, "clientLogin", "клиент");
    const selections = Array.isArray(payload.campaigns) ? payload.campaigns : [];

    if (selections.length === 0) {
      throw new InputError("Не выбраны кампании для очистки.");
    }

    const result = await clearUnavailablePlacements(
      token,
      clientLogin,
      selections,
    );

    sendJson(res, 200, result);
  } catch (error) {
    sendJson(res, error.statusCode || 502, { error: error.message });
  }
}

async function serveStatic(req, res) {
  try {
    const url = new URL(req.url, `http://${host}:${port}`);
    const requestedPath = url.pathname === "/" ? "/index.html" : url.pathname;
    const relativePath = decodeURIComponent(requestedPath).replace(/^\/+/, "");
    const filePath = path.resolve(root, relativePath);

    if (!filePath.startsWith(root)) {
      res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Forbidden");
      return;
    }

    const body = isPortableExecutable
      ? Buffer.from(getAsset(relativePath))
      : await fs.readFile(filePath);
    const contentType = contentTypes[path.extname(filePath).toLowerCase()] || "application/octet-stream";

    res.writeHead(200, {
      "Content-Type": contentType,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
    });
    res.end(req.method === "HEAD" ? undefined : body);
  } catch (error) {
    res.writeHead(error.code === "ENOENT" ? 404 : 500, {
      "Content-Type": "text/plain; charset=utf-8",
    });
    res.end(error.code === "ENOENT" ? "Not found" : "Server error");
  }
}

const server = http.createServer((req, res) => {
  const requestUrl = new URL(req.url, `http://${host}:${port}`);

  if (req.method === "GET" && requestUrl.pathname === "/api/auth/status") {
    handleAuthStatusApi(req, res);
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/auth/login") {
    handleAuthLoginApi(req, res);
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/auth/logout") {
    handleAuthLogoutApi(req, res);
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/shutdown") {
    if (
      !isPortableExecutable ||
      !shutdownToken ||
      req.headers["x-shutdown-token"] !== shutdownToken
    ) {
      sendJson(res, 403, { error: "Forbidden" });
      return;
    }

    sendJson(res, 200, { stopped: true });
    setTimeout(() => {
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(0), 2000).unref();
    }, 50).unref();
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/internal/update-state") {
    if (
      !internalToken ||
      req.headers["x-bm-blocked-internal-token"] !== internalToken
    ) {
      sendJson(res, 403, { error: "Forbidden" });
      return;
    }

    handleInternalUpdateStateApi(req, res);
    return;
  }

  if (requestUrl.pathname.startsWith("/api/") && !readSession(req)) {
    sendJson(res, 401, { error: "Требуется вход в bm-blocked." });
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/direct-clients") {
    handleDirectClientsApi(req, res);
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/blocked-placements") {
    handleBlockedPlacementsApi(req, res);
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/check-placements") {
    handleCheckPlacementsApi(req, res);
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/desktop-notification") {
    handleDesktopNotificationApi(req, res);
    return;
  }

  if (req.method === "GET" && requestUrl.pathname === "/api/update-status") {
    handleUpdateStatusApi(req, res);
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/update-action") {
    handleUpdateActionApi(req, res);
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/clear-placements") {
    handleClearPlacementsApi(req, res);
    return;
  }

  if (req.method === "GET" || req.method === "HEAD") {
    serveStatic(req, res);
    return;
  }

  res.writeHead(405, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Method not allowed");
});

globalThis.bmBlockedServer = server;

let retriedWithRandomPort = false;

server.on("error", (error) => {
  if (
    isPortableExecutable &&
    error.code === "EADDRINUSE" &&
    !retriedWithRandomPort
  ) {
    retriedWithRandomPort = true;
    server.listen(0, host);
    return;
  }

  throw error;
});

server.on("listening", () => {
  const actualPort = server.address().port;
  const appUrl = `http://${host}:${actualPort}/index.html`;

  console.log(`Server is running: ${appUrl}`);

  if (
    isPortableExecutable &&
    process.env.BM_BLOCKED_NO_BROWSER !== "1"
  ) {
    execFile(
      "rundll32.exe",
      ["url.dll,FileProtocolHandler", appUrl],
      { windowsHide: true },
      () => {},
    );
  }
});

server.listen(port, host);

if (isPortableExecutable && parentProcessId > 0) {
  setInterval(() => {
    try {
      process.kill(parentProcessId, 0);
    } catch (error) {
      process.exit(0);
    }
  }, 3000).unref();
}
