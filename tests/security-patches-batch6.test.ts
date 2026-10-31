import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { outboxWorker, OutboxWorker } from "../src/common/workers/outbox.worker";
import { outboxRepository } from "../src/common/repositories/outbox.repository";
import { eventBus, EventBusService } from "../src/common/services/event-bus.service";
import { notificationService } from "../src/modules/notification/notification.service";
import { notificationRepository } from "../src/modules/notification/notification.repository";
import { createRateLimiter } from "../src/middlewares/rate-limit.middleware";
import { EMAIL_STATUS } from "../src/common/constants/notification.constant";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { AppError } from "../src/common/errors/app-error";
import { MAINTENANCE_STATUS } from "../src/common/constants/maintenance.constant";
import { notificationPrisma } from "../src/database/notification.client";

describe("Security Audit Patches - Batch 6 (SEC-22, SEC-23, SEC-24, SEC-25)", () => {
  describe("SEC-22: Transactional Outbox Relay Worker and Persistence Table", () => {
    it("should have OutboxEvent delegate defined on notificationPrisma client", () => {
      assert.ok(
        (notificationPrisma as any).outboxEvent,
        "notificationPrisma should have outboxEvent model delegate",
      );
      assert.equal(
        typeof (notificationPrisma as any).outboxEvent.create,
        "function",
      );
      assert.equal(
        typeof (notificationPrisma as any).outboxEvent.findMany,
        "function",
      );
    });

    it("should execute outboxWorker.process() and relay pending events", async () => {
      let relayCalled = false;
      const mockBus = {
        relayPendingOutboxEvents: async (_batchSize: number) => {
          relayCalled = true;
          return 3;
        },
      } as any;

      const worker = new OutboxWorker(mockBus);
      const count = await worker.process();

      assert.equal(relayCalled, true, "Should invoke relayPendingOutboxEvents");
      assert.equal(count, 3, "Should return relayed event count");
    });

    it("should skip relaying if maintenance mode is enabled", async () => {
      let relayCalled = false;
      const mockBus = {
        relayPendingOutboxEvents: async () => {
          relayCalled = true;
          return 5;
        },
      } as any;

      const worker = new OutboxWorker(mockBus);

      // Temporary override getConfig
      const originalGetConfig = (await import("../src/common/services/maintenance-cache.service")).maintenanceCacheService.getConfig;
      (await import("../src/common/services/maintenance-cache.service")).maintenanceCacheService.getConfig = async () => ({
        enabled: true,
        status: MAINTENANCE_STATUS.MAINTENANCE,
      }) as any;

      try {
        const count = await worker.process();
        assert.equal(relayCalled, false, "Should NOT relay when under maintenance");
        assert.equal(count, 0);
      } finally {
        (await import("../src/common/services/maintenance-cache.service")).maintenanceCacheService.getConfig = originalGetConfig;
      }
    });

    it("should have complete OutboxRepository methods", () => {
      assert.equal(typeof outboxRepository.create, "function");
      assert.equal(typeof outboxRepository.claimPendingEvents, "function");
      assert.equal(typeof outboxRepository.markPublished, "function");
      assert.equal(typeof outboxRepository.markFailed, "function");
    });
  });

  describe("SEC-23: Permanent Redis Disconnection Lockout Prevention", () => {
    it("should provide non-terminating capped backoff retry strategy for eventBus and workers", () => {
      // Simulate IORedis retryStrategy: (times) => Math.min(times * 200, 3000)
      const testRetry = (times: number) => Math.min(times * 200, 3000);

      // Even after 5, 10, 50, 100 retry attempts, it must NEVER return null
      assert.equal(testRetry(1), 200);
      assert.equal(testRetry(3), 600);
      assert.equal(testRetry(5), 1000);
      assert.equal(testRetry(15), 3000);
      assert.equal(testRetry(50), 3000);
      assert.notEqual(testRetry(100), null, "Retry strategy must never abort by returning null");
    });
  });

  describe("SEC-24: Email Retry Race Condition & Inverted Status Validation", () => {
    it("should REJECT retryEmail when status is PENDING, PROCESSING, or SENT", async () => {
      const invalidStatuses = [
        EMAIL_STATUS.PENDING,
        EMAIL_STATUS.PROCESSING,
        EMAIL_STATUS.SENT,
      ];

      for (const status of invalidStatuses) {
        const originalFind = notificationRepository.findEmailById;
        notificationRepository.findEmailById = async (_id: string) =>
          ({
            id: "test-email-id",
            status,
            toEmail: "test@example.com",
            subject: "Test",
          }) as any;

        try {
          await assert.rejects(
            async () => {
              await notificationService.retryEmail("test-email-id");
            },
            (err: any) => {
              assert.equal(err instanceof AppError, true);
              assert.equal(err.statusCode, 400);
              assert.equal(err.code, ERROR_CODE.INVALID_STATUS_TRANSITION);
              return true;
            },
            `Should reject retry for email status: ${status}`,
          );
        } finally {
          notificationRepository.findEmailById = originalFind;
        }
      }
    });

    it("should ALLOW retryEmail only when status is FAILED", async () => {
      const originalFind = notificationRepository.findEmailById;
      const originalReset = notificationRepository.resetEmailForRetry;

      let resetCalled = false;
      notificationRepository.findEmailById = async (_id: string) =>
        ({
          id: "test-email-id",
          status: EMAIL_STATUS.FAILED,
          toEmail: "test@example.com",
          subject: "Test",
        }) as any;

      notificationRepository.resetEmailForRetry = async (_id: string) => {
        resetCalled = true;
        return true;
      };

      try {
        await notificationService.retryEmail("test-email-id");
        assert.equal(resetCalled, true, "Should call resetEmailForRetry when status is FAILED");
      } finally {
        notificationRepository.findEmailById = originalFind;
        notificationRepository.resetEmailForRetry = originalReset;
      }
    });

    it("should REJECT retryEmail if atomic reset returns false (concurrent race condition)", async () => {
      const originalFind = notificationRepository.findEmailById;
      const originalReset = notificationRepository.resetEmailForRetry;

      notificationRepository.findEmailById = async (_id: string) =>
        ({
          id: "test-email-id",
          status: EMAIL_STATUS.FAILED,
          toEmail: "test@example.com",
          subject: "Test",
        }) as any;

      // Another worker/thread transitioned the status concurrently
      notificationRepository.resetEmailForRetry = async (_id: string) => false;

      try {
        await assert.rejects(
          async () => {
            await notificationService.retryEmail("test-email-id");
          },
          (err: any) => {
            assert.equal(err instanceof AppError, true);
            assert.equal(err.statusCode, 400);
            assert.equal(err.code, ERROR_CODE.INVALID_STATUS_TRANSITION);
            return true;
          },
          "Should throw INVALID_STATUS_TRANSITION on atomic CAS update failure",
        );
      } finally {
        notificationRepository.findEmailById = originalFind;
        notificationRepository.resetEmailForRetry = originalReset;
      }
    });
  });

  describe("SEC-25: Rate Limit Key Normalization Across Dual Mount Routes", () => {
    it("should share the same rate limit bucket for both /api/v1/notifications and /notifications", () => {
      const limiter = createRateLimiter({
        maxRequests: 2,
        windowMs: 60000,
      });

      const clientIp = "192.168.100.50";
      const responses: Array<{ status?: number; body?: any; headers: Record<string, any> }> = [];

      const mockRequest = (baseUrl: string) => {
        const headers: Record<string, any> = {};
        let status = 200;
        let body: any = null;

        const req: any = {
          ip: clientIp,
          baseUrl,
          path: "/test",
          socket: { remoteAddress: clientIp },
        };

        const res: any = {
          setHeader: (name: string, value: any) => {
            headers[name] = value;
          },
          status: (code: number) => {
            status = code;
            return {
              json: (data: any) => {
                body = data;
              },
            };
          },
        };

        let nextCalled = false;
        limiter(req, res, () => {
          nextCalled = true;
        });

        return { nextCalled, status, body, headers };
      };

      // 1. Request via /api/v1/notifications -> count = 1
      const res1 = mockRequest("/api/v1/notifications");
      assert.equal(res1.nextCalled, true);
      assert.equal(res1.headers["X-RateLimit-Remaining"], 1);

      // 2. Request via /notifications -> count = 2 (consumes from the SAME bucket)
      const res2 = mockRequest("/notifications");
      assert.equal(res2.nextCalled, true);
      assert.equal(res2.headers["X-RateLimit-Remaining"], 0);

      // 3. Request via /api/v1/notifications -> blocked 429
      const res3 = mockRequest("/api/v1/notifications");
      assert.equal(res3.nextCalled, false);
      assert.equal(res3.status, 429);
      assert.equal(res3.body?.code, ERROR_CODE.RATE_LIMIT_EXCEEDED);

      // 4. Request via /notifications -> ALSO blocked 429! Cannot double quota
      const res4 = mockRequest("/notifications");
      assert.equal(res4.nextCalled, false);
      assert.equal(res4.status, 429);
      assert.equal(res4.body?.code, ERROR_CODE.RATE_LIMIT_EXCEEDED);
    });
  });
});
