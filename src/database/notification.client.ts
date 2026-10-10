import { PrismaClient as NotificationPrismaClient } from "@prisma/client-notification";
import { envConfig } from "../config/env.config";

/**
 * Cấu hình timeout mặc định cho interactive transactions của Notification Service
 */
export const DEFAULT_NOTIFICATION_TRANSACTION_OPTIONS = {
  maxWait: 10000,
  timeout: 15000,
} as const;

let _notificationPrisma: NotificationPrismaClient | null = null;

export function getNotificationPrisma(): NotificationPrismaClient {
  if (!_notificationPrisma) {
    _notificationPrisma = new NotificationPrismaClient({
      log:
        envConfig.nodeEnv === "development"
          ? ["query", "error", "warn"]
          : ["error", "warn"],
    });
  }
  return _notificationPrisma;
}

export const notificationPrisma = new Proxy({} as NotificationPrismaClient, {
  get(_target, prop) {
    return (getNotificationPrisma() as any)[prop];
  },
});
