import { Worker, Job } from "bullmq";
import IORedis from "ioredis";
import { envConfig } from "../../config/env.config";
import { EVENT_BUS_CONSTANTS } from "../constants/event.constant";
import { EventEnvelope } from "../types/event.type";
import { eventBus, EventBusService } from "../services/event-bus.service";

/**
 * EventBus Background Worker (Microservices Phase 3: Event-Driven Backbone)
 *
 * Tiêu thụ các sự kiện được xuất bản từ BullMQ Queue ("events-backbone-queue")
 * và chuyển tiếp tới các subscribers tương ứng qua `dispatchDirectly`.
 */
export class EventBusWorker {
  private worker?: Worker<EventEnvelope>;
  private redisConnection?: IORedis;
  private readonly bus: EventBusService;
  private readonly queueName: string;

  constructor(
    bus?: EventBusService,
    queueName: string = EVENT_BUS_CONSTANTS.DEFAULT_QUEUE_NAME,
  ) {
    this.bus = bus || eventBus;
    this.queueName = queueName;
  }

  start(): void {
    if (!envConfig.redis.enabled || process.env.NODE_ENV === "test") {
      return;
    }

    try {
      this.redisConnection = new IORedis({
        host: envConfig.redis.host,
        port: envConfig.redis.port,
        password: envConfig.redis.password,
        maxRetriesPerRequest: null,
        enableReadyCheck: false,
        retryStrategy: (times) => {
          if (times > 3) return null;
          return Math.min(times * 200, 1000);
        },
      });

      this.worker = new Worker<EventEnvelope>(
        this.queueName,
        async (job: Job<EventEnvelope>) => {
          await this.bus.dispatchDirectly(job.data);
        },
        {
          connection: this.redisConnection,
          concurrency: 10,
        },
      );

      this.worker.on("completed", (job) => {
        console.log(
          `[EventBusWorker] ✅ Processed event job [${job.data.name}] ID: ${job.data.id}`,
        );
      });

      this.worker.on("failed", (job, err) => {
        console.error(
          `[EventBusWorker] ❌ Event job [${job?.data?.name}] ID: ${job?.data?.id} failed:`,
          err.message,
        );
      });

      console.log(
        `[EventBusWorker] 🚀 Started — listening to queue: ${this.queueName}`,
      );
    } catch (err: any) {
      console.warn(
        "[EventBusWorker] Could not connect to Redis for EventBus Worker:",
        err?.message,
      );
    }
  }

  async stop(): Promise<void> {
    if (this.worker) {
      await this.worker.close().catch(() => {});
    }
    if (this.redisConnection) {
      this.redisConnection.disconnect();
    }
    console.log("[EventBusWorker] Stopped cleanly");
  }
}

export const eventBusWorker = new EventBusWorker();
