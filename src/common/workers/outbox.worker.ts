import { eventBus, EventBusService } from "../services/event-bus.service";
import { EVENT_BUS_CONSTANTS } from "../constants/event.constant";
import { maintenanceCacheService } from "../services/maintenance-cache.service";
import { MAINTENANCE_STATUS } from "../constants/maintenance.constant";

export class OutboxWorker {
  private readonly bus: EventBusService;
  private intervalId?: ReturnType<typeof setInterval>;
  private isRunning = false;
  private activeRelayPromise?: Promise<number>;

  constructor(bus?: EventBusService) {
    this.bus = bus || eventBus;
  }

  start(
    intervalMs: number = EVENT_BUS_CONSTANTS.OUTBOX_POLL_INTERVAL_MS,
  ): void {
    if (this.intervalId || process.env.NODE_ENV === "test") return;

    console.log(
      `[OutboxWorker] 📬 Started — polling outbox every ${intervalMs / 1000}s`,
    );

    // Chạy lần đầu ngay khi start
    this.process();

    this.intervalId = setInterval(() => {
      this.process();
    }, intervalMs);
  }

  async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = undefined;
    }
    if (this.activeRelayPromise) {
      await this.activeRelayPromise.catch(() => {});
    }
    console.log("[OutboxWorker] Stopped cleanly");
  }

  public async process(): Promise<number> {
    if (this.isRunning) return 0;
    this.isRunning = true;

    this.activeRelayPromise = (async () => {
      try {
        const maintenanceConfig = await maintenanceCacheService
          .getConfig()
          .catch(() => null);
        if (
          maintenanceConfig &&
          maintenanceConfig.enabled &&
          maintenanceConfig.status === MAINTENANCE_STATUS.MAINTENANCE
        ) {
          return 0;
        }

        const relayedCount = await this.bus.relayPendingOutboxEvents(
          EVENT_BUS_CONSTANTS.OUTBOX_BATCH_SIZE,
        );

        if (relayedCount > 0) {
          console.log(
            `[OutboxWorker] 🚀 Successfully relayed ${relayedCount} outbox event(s)`,
          );
        }
        return relayedCount;
      } catch (err: any) {
        console.warn("[OutboxWorker] Relay batch error:", err?.message || err);
        return 0;
      } finally {
        this.isRunning = false;
        this.activeRelayPromise = undefined;
      }
    })();

    return (await this.activeRelayPromise) || 0;
  }
}

export const outboxWorker = new OutboxWorker();
