import { envConfig } from "../../config/env.config";
import { ZALO_BOT_MODE } from "../constants/notification.constant";
import { isAutomatedTestRuntime } from "../helpers/runtime.helper";
import {
  zaloBotClient,
  ZaloBotClient,
  redactBotToken,
} from "../services/zalo-bot.client";
import {
  zaloBotService,
  ZaloBotService,
} from "../../modules/zalo-bot/zalo-bot.service";

const DEFAULT_BACKOFF_SCHEDULE_MS = [2_000, 5_000, 15_000, 30_000];

export interface ZaloBotPollingWorkerOptions {
  allowInTest?: boolean;
  backoffScheduleMs?: number[];
  pollingTimeoutSeconds?: number;
}

export class ZaloBotPollingWorker {
  private stopped = true;
  private abortController?: AbortController;
  private loopPromise?: Promise<void>;
  private readonly allowInTest: boolean;
  private readonly backoffScheduleMs: number[];
  private readonly pollingTimeoutSeconds: number;

  constructor(
    private readonly client: ZaloBotClient = zaloBotClient,
    private readonly service: ZaloBotService = zaloBotService,
    options: ZaloBotPollingWorkerOptions = {},
  ) {
    this.allowInTest = Boolean(options.allowInTest);
    this.backoffScheduleMs =
      options.backoffScheduleMs && options.backoffScheduleMs.length > 0
        ? options.backoffScheduleMs
        : DEFAULT_BACKOFF_SCHEDULE_MS;
    this.pollingTimeoutSeconds =
      options.pollingTimeoutSeconds ?? envConfig.zaloBot.pollingTimeoutSeconds;
  }

  start(): void {
    if (!this.allowInTest && isAutomatedTestRuntime()) {
      return;
    }

    if (!this.allowInTest && envConfig.zaloBot.mode !== ZALO_BOT_MODE.POLLING) {
      console.log(
        `[ZaloBotPollingWorker] Idle (ZALO_BOT_MODE=${envConfig.zaloBot.mode})`,
      );
      return;
    }

    if (!this.client.isConfigured()) {
      console.warn(
        "[ZaloBotPollingWorker] Disabled — ZALO_BOT_MODE=polling nhưng chưa cấu hình ZALO_BOT_TOKEN.",
      );
      return;
    }

    if (!this.stopped) return;
    this.stopped = false;
    this.abortController = new AbortController();

    console.log(
      `[ZaloBotPollingWorker] Started long-polling (timeout=${this.pollingTimeoutSeconds}s)`,
    );

    this.loopPromise = this.runLoop();
  }

  async stop(): Promise<void> {
    if (this.stopped) return;
    this.stopped = true;
    this.abortController?.abort();
    if (this.loopPromise) {
      await this.loopPromise.catch(() => {});
    }
    console.log("[ZaloBotPollingWorker] Stopped cleanly");
  }

  private async sleepWithAbort(ms: number): Promise<void> {
    if (this.stopped) return;
    await new Promise<void>((resolve) => {
      const signal = this.abortController?.signal;
      const onAbort = () => {
        clearTimeout(timer);
        resolve();
      };
      const timer = setTimeout(() => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      }, ms);
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  }

  private async runLoop(): Promise<void> {
    // getUpdates không hoạt động nếu webhook đang được thiết lập trước đó (docs/apis/getUpdates)
    try {
      await this.client.deleteWebhook(this.abortController?.signal);
    } catch (err: any) {
      if (this.stopped) return;
      console.warn(
        "[ZaloBotPollingWorker] Warning deleting existing webhook before polling:",
        redactBotToken(err?.message || String(err)),
      );
    }

    let consecutiveErrors = 0;

    while (!this.stopped) {
      try {
        const updates = await this.client.getUpdates(
          this.pollingTimeoutSeconds,
          this.abortController?.signal,
        );
        consecutiveErrors = 0;

        for (const update of updates) {
          if (this.stopped) break;
          await this.service.processUpdate(update).catch((err: any) => {
            console.warn(
              "[ZaloBotPollingWorker] Failed to process update:",
              redactBotToken(err?.message || String(err)),
            );
          });
        }
      } catch (err: any) {
        if (this.stopped) break;
        consecutiveErrors++;
        const backoffMs =
          this.backoffScheduleMs[
            Math.min(consecutiveErrors - 1, this.backoffScheduleMs.length - 1)
          ];
        console.warn(
          `[ZaloBotPollingWorker] Polling error (retry in ${backoffMs / 1000}s):`,
          redactBotToken(err?.message || String(err)),
        );
        await this.sleepWithAbort(backoffMs);
      }
    }
  }
}

export const zaloBotPollingWorker = new ZaloBotPollingWorker();
