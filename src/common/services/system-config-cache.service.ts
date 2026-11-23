import IORedis from "ioredis";
import { envConfig } from "../../config/env.config";
import { GATEWAY_HEADERS } from "../constants/gateway.constant";
import { SYSTEM_CONFIG_PUBSUB_CHANNEL } from "../constants/system-config.constant";

function isAutomatedTestRuntime(): boolean {
  return (
    process.env.NODE_ENV === "test" ||
    Boolean(process.env.NODE_TEST_CONTEXT)
  );
}

/**
 * Chuẩn hóa giá trị Feature Flag từ API/PubSub về boolean an toàn.
 * Tránh lỗi `Boolean("false") === true` khi flag lưu dạng chuỗi.
 */
export function parseBooleanFlag(value: unknown, defaultState = true): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (["false", "0", "off", "no", ""].includes(normalized)) return false;
    if (["true", "1", "on", "yes"].includes(normalized)) return true;
    return defaultState;
  }
  if (value && typeof value === "object" && "enabled" in value) {
    return parseBooleanFlag(
      (value as { enabled?: unknown }).enabled,
      defaultState,
    );
  }
  return value === undefined || value === null ? defaultState : Boolean(value);
}

interface CacheEntry {
  value: unknown;
  expiresAt: number;
}

export class SystemConfigCacheService {
  private cache = new Map<string, CacheEntry>();
  private overrides = new Map<string, unknown>();
  private readonly TTL_MS = 30_000;
  private redisSubscriber?: IORedis;
  private readonly customFetcher?: () => Promise<Record<string, unknown> | null>;

  constructor(customFetcher?: () => Promise<Record<string, unknown> | null>) {
    this.customFetcher = customFetcher;
    if (!isAutomatedTestRuntime() && envConfig.redis.enabled && !customFetcher) {
      this.initRedisPubSub();
    }
  }

  private initRedisPubSub(): void {
    try {
      this.redisSubscriber = new IORedis({
        host: envConfig.redis.host,
        port: envConfig.redis.port,
        password: envConfig.redis.password,
        maxRetriesPerRequest: null,
        enableReadyCheck: false,
        lazyConnect: true,
        retryStrategy: (times: number) => Math.min(times * 500, 30_000),
      });

      this.redisSubscriber.on("connect", () => {
        this.redisSubscriber?.subscribe(SYSTEM_CONFIG_PUBSUB_CHANNEL, (err) => {
          if (err) {
            console.error(
              "[SystemConfigCache] Redis subscribe error:",
              err.message,
            );
          }
        });
      });

      this.redisSubscriber.on("message", (channel, message) => {
        this.handlePubSubMessage(channel, message);
      });

      this.redisSubscriber.on("error", () => {
        // Fallback an toàn về HTTP polling TTL nếu Redis không khả dụng
      });

      this.redisSubscriber.connect().catch(() => {});
    } catch {
      // Ignore init error when Redis is offline
    }
  }

  /**
   * Xử lý thông điệp từ kênh Redis `system_config:events` để hot-toggle tức thì.
   */
  handlePubSubMessage(channel: string, message: string): void {
    if (channel !== SYSTEM_CONFIG_PUBSUB_CHANNEL) return;
    try {
      const data = JSON.parse(message) as { key?: unknown; value?: unknown };
      if (data && typeof data.key === "string") {
        if ("value" in data && data.value !== undefined) {
          this.cache.set(data.key, {
            value: data.value,
            expiresAt: Date.now() + this.TTL_MS,
          });
        } else {
          this.cache.delete(data.key);
        }
      } else {
        this.cache.clear();
      }
    } catch {
      this.cache.clear();
    }
  }

  setOverride(key: string, value: unknown): void {
    this.overrides.set(key, value);
  }

  clearOverrides(): void {
    this.overrides.clear();
  }

  clearCache(): void {
    this.cache.clear();
  }

  private async fetchPublicConfigs(): Promise<Record<string, unknown> | null> {
    if (this.customFetcher) {
      return this.customFetcher();
    }

    const baseUrl = envConfig.identity.serviceUrl;
    if (!baseUrl) {
      return null;
    }

    const headers: Record<string, string> = {
      Accept: "application/json",
    };
    if (envConfig.gateway.internalSecret) {
      headers[GATEWAY_HEADERS.INTERNAL_SECRET] =
        envConfig.gateway.internalSecret;
    }
    if (envConfig.internalService.token) {
      headers[GATEWAY_HEADERS.INTERNAL_SERVICE_TOKEN] =
        envConfig.internalService.token;
    }

    const res = await fetch(
      `${baseUrl.replace(/\/+$/, "")}/api/v1/system/public`,
      {
        method: "GET",
        headers,
        signal: AbortSignal.timeout(3000),
      },
    );

    if (!res.ok) {
      return null;
    }

    const body = (await res.json()) as { data?: Record<string, unknown> };
    const configs = body?.data ?? (body as unknown as Record<string, unknown>);
    return configs && typeof configs === "object" ? configs : null;
  }

  async get<T = unknown>(key: string, defaultValue?: T): Promise<T> {
    if (this.overrides.has(key)) {
      return this.overrides.get(key) as T;
    }

    const cached = this.cache.get(key);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.value as T;
    }

    if (isAutomatedTestRuntime() && !this.customFetcher) {
      return defaultValue as T;
    }

    try {
      const configs = await this.fetchPublicConfigs();
      if (configs) {
        const expiresAt = Date.now() + this.TTL_MS;
        for (const [cfgKey, cfgVal] of Object.entries(configs)) {
          this.cache.set(cfgKey, { value: cfgVal, expiresAt });
        }
        if (Object.prototype.hasOwnProperty.call(configs, key)) {
          return configs[key] as T;
        }
        // Key was removed or made private upstream: drop expired entry instead of serving stale cache
        this.cache.delete(key);
        return defaultValue as T;
      }
    } catch {
      // Fallback sang giá trị cache cũ (nếu có) hoặc defaultValue
    }

    if (cached) {
      return cached.value as T;
    }

    return defaultValue as T;
  }

  async isFeatureEnabled(
    flagKey: string,
    defaultState = true,
  ): Promise<boolean> {
    try {
      const val = await this.get<unknown>(flagKey, defaultState);
      return parseBooleanFlag(val, defaultState);
    } catch {
      return defaultState;
    }
  }

  async close(): Promise<void> {
    this.cache.clear();
    this.overrides.clear();
    if (this.redisSubscriber) {
      this.redisSubscriber.disconnect();
      this.redisSubscriber = undefined;
    }
  }
}

export const systemConfigCacheService = new SystemConfigCacheService();
