import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { isUuid, UUID_REGEX } from "../src/common/helpers/uuid.helper";
import { eventBus } from "../src/common/services/event-bus.service";
import { notificationRepository } from "../src/modules/notification/notification.repository";
import { NotificationService } from "../src/modules/notification/notification.service";
import { envConfig } from "../src/config/env.config";
import {
  NOTIFICATION_CHANNEL,
  NOTIFICATION_SEVERITY,
} from "../src/common/constants/notification.constant";

describe("Security Audit Patches - Batch 5 (SEC-17, SEC-18, SEC-19, SEC-20, SEC-21)", () => {
  describe("SEC-17: Template & Action Audit Logging EventBus Ingestion", () => {
    it("should publish audit event to EventBus when createAuditLog is invoked with valid actorId", async () => {
      let publishedEventName = "";
      let publishedPayload: any = null;

      const origPublish = eventBus.publish;
      (eventBus as any).publish = async (eventName: string, payload: any) => {
        publishedEventName = eventName;
        publishedPayload = payload;
        return { id: "mock-evt-1" };
      };

      try {
        const result = await notificationRepository.createAuditLog({
          actorId: "018f6e7c-8901-789a-bcde-f0123456789a",
          action: "CREATE_NOTIFICATION_TEMPLATE",
          targetType: "NOTIFICATION_TEMPLATE",
          targetId: "tpl-001",
          details: { name: "Safety Warning Alert" },
        });

        assert.ok(result, "createAuditLog must return audit metadata");
        assert.equal(publishedEventName, "audit.action.created");
        assert.equal(publishedPayload.userId, "018f6e7c-8901-789a-bcde-f0123456789a");
        assert.equal(publishedPayload.action, "CREATE_NOTIFICATION_TEMPLATE");
        assert.equal(publishedPayload.targetType, "NOTIFICATION_TEMPLATE");
        assert.equal(publishedPayload.targetId, "tpl-001");
      } finally {
        (eventBus as any).publish = origPublish;
      }
    });

    it("should return null and skip publish when actorId is missing or invalid UUID", async () => {
      let publishCalled = false;
      const origPublish = eventBus.publish;
      (eventBus as any).publish = async () => {
        publishCalled = true;
      };

      try {
        const result = await notificationRepository.createAuditLog({
          actorId: "invalid-actor-id",
          action: "UPDATE_TEMPLATE",
          targetType: "TEMPLATE",
        });

        assert.equal(result, null);
        assert.equal(publishCalled, false);
      } finally {
        (eventBus as any).publish = origPublish;
      }
    });
  });

  describe("SEC-18: Multi-Pod Distributed Idempotency Protection", () => {
    it("should detect duplicate event IDs within idempotency window", async () => {
      const testEventId = "018f6e7c-8901-789a-bcde-f0123456789b";

      // Initially, event has not been processed
      assert.equal(await eventBus.isEventAlreadyProcessed(testEventId), false);

      // Mark processed
      await eventBus.markEventProcessed(testEventId);

      // Subsequent check must return true (idempotent protection)
      assert.equal(await eventBus.isEventAlreadyProcessed(testEventId), true);
    });

    it("should check and store in Redis when connection is active", async () => {
      let redisGetCalled = false;
      let redisSetCalled = false;

      const mockRedis: any = {
        get: async (key: string) => {
          redisGetCalled = true;
          return "1";
        },
        set: async (key: string, val: string, ex: string, ttl: number) => {
          redisSetCalled = true;
        },
      };

      const origConn = (eventBus as any).redisConnection;
      const origAvailable = (eventBus as any).isRedisAvailable;

      try {
        (eventBus as any).redisConnection = mockRedis;
        (eventBus as any).isRedisAvailable = true;

        const isProcessed = await eventBus.isEventAlreadyProcessed("evt-redis-123");
        assert.equal(isProcessed, true);
        assert.equal(redisGetCalled, true);

        await eventBus.markEventProcessed("evt-redis-456");
        assert.equal(redisSetCalled, true);
      } finally {
        (eventBus as any).redisConnection = origConn;
        (eventBus as any).isRedisAvailable = origAvailable;
      }
    });
  });

  describe("SEC-19: Strict RFC-Compliant UUID Validation", () => {
    it("should accept valid UUIDv4, UUIDv7 and nil UUIDs", () => {
      assert.equal(isUuid("018f6e7c-8901-789a-bcde-f0123456789a"), true);
      assert.equal(isUuid("123e4567-e89b-12d3-a456-426614174000"), true);
      assert.equal(isUuid("00000000-0000-0000-0000-000000000000"), true);
    });

    it("should REJECT malformed UUIDs with 36 hyphens or non-hyphenated strings", () => {
      const allHyphens = "------------------------------------";
      assert.equal(isUuid(allHyphens), false, "36 hyphens must be rejected");

      const thirtySixZeroes = "000000000000000000000000000000000000";
      assert.equal(isUuid(thirtySixZeroes), false, "UUID without hyphens must be rejected");

      assert.equal(isUuid("123-456-789-abc-def-123-456-789-abc"), false);
      assert.equal(isUuid(""), false);
      assert.equal(isUuid(null), false);
      assert.equal(isUuid(undefined), false);
    });
  });

  describe("SEC-20: Network Trust Proxy Misconfiguration Hardening", () => {
    it("should resolve trustProxy to number 1 or specific hops rather than boolean true", () => {
      // Trust proxy should not be true (which enables blind leftmost IP trust)
      assert.notEqual(envConfig.trustProxy, true);
      assert.ok(
        typeof envConfig.trustProxy === "number" ||
          typeof envConfig.trustProxy === "string" ||
          Array.isArray(envConfig.trustProxy) ||
          envConfig.trustProxy === false,
      );
    });
  });

  describe("SEC-21: Recipient Array Deduplication Against Notification Bombing", () => {
    it("should deduplicate recipientUserIds in dispatchIncidentNotification", async () => {
      let createdRecords: any[] = [];
      let sseSendCount = 0;

      const mockRepository: any = {
        findUserPreferences: async () => [
          { channel: NOTIFICATION_CHANNEL.IN_APP, enabled: true, severityThreshold: "LOW" },
        ],
        createManyNotifications: async (records: any[]) => {
          createdRecords = records;
          return { count: records.length };
        },
      };

      const mockSse: any = {
        sendToUser: () => {
          sseSendCount++;
        },
      };

      const mockMail: any = {
        sendPpeViolationAlertEmail: async () => {},
      };

      const service = new NotificationService(mockRepository, mockMail, mockSse);

      const duplicateUser = "018f6e7c-8901-789a-bcde-f0123456789a";
      // Pass the same user ID 5 times
      const result = await service.dispatchIncidentNotification({
        incidentId: "018f6e7c-8901-789a-bcde-f01234567890",
        siteId: "018f6e7c-8901-789a-bcde-f01234567891",
        cameraId: "018f6e7c-8901-789a-bcde-f01234567892",
        violationType: "NO_HELMET",
        severity: NOTIFICATION_SEVERITY.HIGH,
        recipientUserIds: [
          duplicateUser,
          duplicateUser,
          duplicateUser,
          duplicateUser,
          duplicateUser,
        ],
      });

      // Must be deduplicated to exactly 1 recipient (1 in-app + 1 email = 2 records/dispatches instead of 5 * 2 = 10)
      assert.equal(createdRecords.length, 2, "Only 1 in-app and 1 email record created for the single deduplicated user");
      assert.equal(sseSendCount, 1, "Only 1 SSE notification should be sent");
      assert.equal(result.dispatchedCount, 2, "1 in-app + 1 email = 2 dispatches total");
    });

    it("should deduplicate userIds and channels in sendNotification", async () => {
      let createdRecords: any[] = [];

      const mockRepository: any = {
        createManyNotifications: async (records: any[]) => {
          createdRecords = records;
          return { count: records.length };
        },
      };

      const mockSse: any = {
        sendToUser: () => {},
      };

      const service = new NotificationService(mockRepository, {} as any, mockSse);

      const targetUser = "018f6e7c-8901-789a-bcde-f0123456789a";
      await service.send({
        userIds: [targetUser, targetUser, targetUser],
        channels: [NOTIFICATION_CHANNEL.IN_APP, NOTIFICATION_CHANNEL.IN_APP],
        title: "Test Alert",
        content: "Test alert content",
      });

      // 1 user * 1 channel = 1 record (instead of 3 * 2 = 6 redundant records)
      assert.equal(createdRecords.length, 1);
    });
  });
});
