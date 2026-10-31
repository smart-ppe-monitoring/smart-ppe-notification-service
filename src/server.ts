import "dotenv/config";
import dns from "node:dns";

// Force IPv4-first resolution in Node.js runtime to prevent ENETUNREACH on platforms without IPv6 routing
try {
  dns.setDefaultResultOrder("ipv4first");
} catch {
  // Graceful fallback if not supported in runtime
}

import notificationApp from "./notification.app";
import { envConfig } from "./config/env.config";
import { emailWorker } from "./common/workers/email-worker";
import { outboxWorker } from "./common/workers/outbox.worker";
import { EventBusWorker } from "./common/workers/event-bus.worker";
import { EVENT_BUS_CONSTANTS } from "./common/constants/event.constant";
import { notificationSubscriber } from "./common/subscribers/notification.subscriber";
import { eventBus } from "./common/services/event-bus.service";
import { sseManagerService } from "./common/services/sse-manager.service";
import { notificationPrisma } from "./database/notification.client";

const PORT = envConfig.notification.port;

/**
 * Notification Microservice Process (Phase 5: First Satellite Service)
 *
 * Chịu trách nhiệm độc quyền:
 * 1. Phục vụ HTTP API cho Notification domain (REST & SSE Stream)
 * 2. Lắng nghe các event topics từ Redis EventBus qua NotificationSubscriber
 * 3. Xử lý hàng đợi gửi email bất đồng bộ qua EmailWorker (SMTP / Resend)
 */
export const notificationEventBusWorker = new EventBusWorker(
  eventBus,
  EVENT_BUS_CONSTANTS.NOTIFICATION_QUEUE_NAME,
);

export const server = notificationApp.listen(PORT, async () => {
  console.log(
    `[Notification Service] Running on http://localhost:${PORT} in ${envConfig.nodeEnv} mode`,
  );

  // 1. Đăng ký subscriber lắng nghe events từ Auth & Core services
  notificationSubscriber.register();

  // 2. Khởi chạy EventBus worker (chuyên biệt cho notification queue), Outbox worker và Email worker
  notificationEventBusWorker.start();
  outboxWorker.start();
  emailWorker.start();

  console.log(
    "[Notification Service] ✅ NotificationSubscriber, NotificationEventBusWorker, OutboxWorker and EmailWorker are active.",
  );
});

let isShuttingDown = false;

export async function handleNotificationShutdown(
  signal: string,
): Promise<void> {
  if (isShuttingDown) return;
  isShuttingDown = true;

  console.log(
    `\n[Notification Service] Received ${signal}. Starting graceful shutdown...`,
  );

  const forceExitTimer = setTimeout(() => {
    console.error(
      "[Notification Service] Graceful shutdown timed out (10s). Forcing termination.",
    );
    process.exit(1);
  }, 10000);
  forceExitTimer.unref();

  try {
    // 1. Close idle HTTP connections
    if (typeof server.closeIdleConnections === "function") {
      server.closeIdleConnections();
    }

    // 2. Stop accepting new HTTP requests
    await new Promise<void>((resolve) => {
      server.close((err) => {
        if (err) {
          console.warn(
            "[Notification Service] Warning while closing HTTP server:",
            err.message,
          );
        } else {
          console.log("[Notification Service] HTTP server closed.");
        }
        resolve();
      });
    });

    // 3. Stop background workers
    await Promise.allSettled([
      emailWorker.stop(),
      notificationEventBusWorker.stop(),
      outboxWorker.stop(),
    ]);
    console.log(
      "[Notification Service] EmailWorker, NotificationEventBusWorker & OutboxWorker stopped.",
    );

    // 4. Close SSE connections & EventBus
    await sseManagerService.close();
    await eventBus.close();
    console.log("[Notification Service] SSE and EventBus connections closed.");

    // 5. Disconnect Prisma DB clients
    await notificationPrisma.$disconnect().catch(() => {});
    console.log("[Notification Service] Database clients disconnected.");

    console.log("[Notification Service] Graceful shutdown completed cleanly.");
    clearTimeout(forceExitTimer);
    if (process.env.NODE_ENV !== "test") {
      process.exit(0);
    }
  } catch (err: any) {
    console.error(
      "[Notification Service] Error during graceful shutdown:",
      err.message,
    );
    clearTimeout(forceExitTimer);
    if (process.env.NODE_ENV !== "test") {
      process.exit(1);
    }
  }
}

process.on("SIGTERM", () => handleNotificationShutdown("SIGTERM"));
process.on("SIGINT", () => handleNotificationShutdown("SIGINT"));
