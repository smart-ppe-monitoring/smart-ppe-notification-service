import { describe, it } from "node:test";
import assert from "node:assert/strict";
import jwt from "jsonwebtoken";
import {
  NOTIFICATION_CHANNEL,
  NOTIFICATION_SEVERITY,
  NOTIFICATION_STATUS,
  NOTIFICATION_TEMPLATE_CODE,
  SEVERITY_WEIGHT,
  DEFAULT_PREFERENCES,
} from "../src/common/constants/notification.constant";
import {
  dispatchIncidentNotificationSchema,
  updateNotificationPreferenceSchema,
  listNotificationsSchema,
} from "../src/modules/notification/notification.validation";
import { NotificationService } from "../src/modules/notification/notification.service";
import { NotificationRepository } from "../src/modules/notification/notification.repository";
import { UserRepository } from "../src/modules/users/user.repository";
import { MailService } from "../src/common/services/mail.service";
import { SseManagerService } from "../src/common/services/sse-manager.service";
import { IncidentService } from "../src/modules/incident/incident.service";
import { IncidentRepository } from "../src/modules/incident/incident.repository";
import { jwtConfig } from "../src/config/jwt.config";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";

describe("Task BE-08: PPE Incident Notification Service Suite", () => {
  const fakeIncidentId = "11111111-1111-4111-8111-111111111111";
  const fakeSiteId = "22222222-2222-4222-8222-222222222222";
  const fakeCameraId = "33333333-3333-4333-8333-333333333333";
  const fakeSafetyOfficerId = "44444444-4444-4444-8444-444444444444";
  const fakeSafetyManagerId = "55555555-5555-4555-8555-555555555555";
  const fakeNotificationId = "66666666-6666-4666-8666-666666666666";

  // ── 1. Domain Constants & Priority Weights ──────────────────────────────────
  describe("1. Notification Domain Constants & Channel Rules", () => {
    it("should define standard multi-channel notification constants", () => {
      assert.equal(NOTIFICATION_CHANNEL.IN_APP, "IN_APP");
      assert.equal(NOTIFICATION_CHANNEL.WEB, "WEB");
      assert.equal(NOTIFICATION_CHANNEL.EMAIL, "EMAIL");
      assert.equal(NOTIFICATION_CHANNEL.ZALO_ZNS, "ZALO_ZNS");
      assert.equal(NOTIFICATION_CHANNEL.WEBHOOK, "WEBHOOK");
    });

    it("should define PPE severity levels and status constants", () => {
      assert.equal(NOTIFICATION_SEVERITY.LOW, "LOW");
      assert.equal(NOTIFICATION_SEVERITY.NORMAL, "NORMAL");
      assert.equal(NOTIFICATION_SEVERITY.MEDIUM, "MEDIUM");
      assert.equal(NOTIFICATION_SEVERITY.HIGH, "HIGH");
      assert.equal(NOTIFICATION_SEVERITY.CRITICAL, "CRITICAL");

      assert.equal(NOTIFICATION_STATUS.PENDING, "PENDING");
      assert.equal(NOTIFICATION_STATUS.SENT, "SENT");
      assert.equal(NOTIFICATION_STATUS.FAILED, "FAILED");
      assert.equal(NOTIFICATION_STATUS.READ, "READ");
    });

    it("should verify severity hierarchy weight to support alert threshold filtering", () => {
      assert.ok(SEVERITY_WEIGHT.CRITICAL > SEVERITY_WEIGHT.HIGH);
      assert.ok(SEVERITY_WEIGHT.HIGH > SEVERITY_WEIGHT.MEDIUM);
      assert.ok(SEVERITY_WEIGHT.MEDIUM >= SEVERITY_WEIGHT.NORMAL);
      assert.ok(SEVERITY_WEIGHT.NORMAL > SEVERITY_WEIGHT.LOW);
    });

    it("should provide sensible default preferences for new safety officers", () => {
      assert.equal(DEFAULT_PREFERENCES.length, 2);
      const inAppDef = DEFAULT_PREFERENCES.find((p) => p.channel === NOTIFICATION_CHANNEL.IN_APP);
      const emailDef = DEFAULT_PREFERENCES.find((p) => p.channel === NOTIFICATION_CHANNEL.EMAIL);

      assert.ok(inAppDef);
      assert.equal(inAppDef.enabled, true);
      assert.equal(inAppDef.severityThreshold, NOTIFICATION_SEVERITY.LOW);

      assert.ok(emailDef);
      assert.equal(emailDef.enabled, true);
      assert.equal(emailDef.severityThreshold, NOTIFICATION_SEVERITY.HIGH);
    });
  });

  // ── 2. Request Validation Schemas ──────────────────────────────────────────
  describe("2. Request Validation Schemas (Zod)", () => {
    it("should accept valid payload for PPE Incident notification dispatch", () => {
      const validPayload = {
        incidentId: fakeIncidentId,
        siteId: fakeSiteId,
        cameraId: fakeCameraId,
        cameraCode: "CAM-GATE-01",
        siteName: "Công trường Landmark",
        violationType: "NO_HELMET",
        severity: "HIGH",
        description: "Công nhân không đội mũ bảo hộ tại cổng chính",
        evidenceUrl: "http://minio.local/ppe-evidences/snapshot.jpg",
        recipientUserIds: [fakeSafetyOfficerId],
      };

      const result = dispatchIncidentNotificationSchema.safeParse(validPayload);
      assert.equal(result.success, true);
    });

    it("should reject incident dispatch payload with invalid UUID format", () => {
      const invalidPayload = {
        incidentId: "invalid-uuid-format",
        violationType: "NO_HELMET",
        severity: "HIGH",
      };

      const result = dispatchIncidentNotificationSchema.safeParse(invalidPayload);
      assert.equal(result.success, false);
    });

    it("should reject incident dispatch payload with unknown severity level", () => {
      const invalidPayload = {
        incidentId: fakeIncidentId,
        violationType: "NO_HELMET",
        severity: "SUPER_DANGEROUS", // không thuộc LOW, NORMAL, MEDIUM, HIGH, CRITICAL
      };

      const result = dispatchIncidentNotificationSchema.safeParse(invalidPayload);
      assert.equal(result.success, false);
    });

    it("should validate and parse updateNotificationPreferenceSchema", () => {
      const validPref = {
        channel: NOTIFICATION_CHANNEL.EMAIL,
        enabled: true,
        severityThreshold: NOTIFICATION_SEVERITY.CRITICAL,
      };

      const result = updateNotificationPreferenceSchema.safeParse(validPref);
      assert.equal(result.success, true);
    });

    it("should parse boolean string in listNotificationsSchema query", () => {
      const parsedTrue = listNotificationsSchema.parse({ isRead: "true" });
      assert.equal(parsedTrue.isRead, true);

      const parsedFalse = listNotificationsSchema.parse({ isRead: "false" });
      assert.equal(parsedFalse.isRead, false);
    });
  });

  // ── 3. Notification Preferences & Severity Filtering ───────────────────────
  describe("3. Notification Preferences & Alert Threshold Filtering", () => {
    it("should NOT dispatch Email when incident severity is lower than user threshold", async () => {
      let emailSent = false;
      let sseSent = false;

      const mockRepo = {
        findUserPreferences: async (_userId: string) => [
          { channel: NOTIFICATION_CHANNEL.IN_APP, enabled: true, severityThreshold: NOTIFICATION_SEVERITY.LOW },
          { channel: NOTIFICATION_CHANNEL.EMAIL, enabled: true, severityThreshold: NOTIFICATION_SEVERITY.HIGH },
        ],
        createManyNotifications: async () => ({ count: 1 }),
      } as unknown as NotificationRepository;

      const mockUserRepo = {
        findActiveUsersByIds: async (ids: string[]) => [
          { id: ids[0], email: "officer@ppe.vn" },
        ],
      } as unknown as UserRepository;

      const mockMail = {
        sendPpeViolationAlertEmail: async () => {
          emailSent = true;
        },
      } as unknown as MailService;

      const mockSse = {
        sendToUser: () => {
          sseSent = true;
        },
      } as unknown as SseManagerService;

      const service = new NotificationService(mockRepo, mockUserRepo, mockMail, mockSse);

      const result = await service.dispatchIncidentNotification({
        incidentId: fakeIncidentId,
        violationType: "NO_VEST",
        severity: "LOW", // LOW < HIGH threshold của Email
        recipientUserIds: [fakeSafetyOfficerId],
      });

      assert.equal(sseSent, true, "In-App SSE phải được gửi vì threshold là LOW");
      assert.equal(emailSent, false, "Email không được gửi vì sự cố LOW dưới ngưỡng HIGH");
      assert.ok(result.channels.includes(NOTIFICATION_CHANNEL.IN_APP));
      assert.ok(!result.channels.includes(NOTIFICATION_CHANNEL.EMAIL));
    });

    it("should dispatch BOTH In-App and Email when incident severity meets or exceeds threshold", async () => {
      let emailSent = false;
      let sseSent = false;

      const mockRepo = {
        findUserPreferences: async () => [
          { channel: NOTIFICATION_CHANNEL.IN_APP, enabled: true, severityThreshold: NOTIFICATION_SEVERITY.LOW },
          { channel: NOTIFICATION_CHANNEL.EMAIL, enabled: true, severityThreshold: NOTIFICATION_SEVERITY.HIGH },
        ],
        createManyNotifications: async () => ({ count: 2 }),
      } as unknown as NotificationRepository;

      const mockUserRepo = {
        findActiveUsersByIds: async (ids: string[]) => [
          { id: ids[0], email: "manager@ppe.vn" },
        ],
      } as unknown as UserRepository;

      const mockMail = {
        sendPpeViolationAlertEmail: async () => {
          emailSent = true;
        },
      } as unknown as MailService;

      const mockSse = {
        sendToUser: () => {
          sseSent = true;
        },
      } as unknown as SseManagerService;

      const service = new NotificationService(mockRepo, mockUserRepo, mockMail, mockSse);

      const result = await service.dispatchIncidentNotification({
        incidentId: fakeIncidentId,
        violationType: "NO_HELMET",
        severity: "CRITICAL", // CRITICAL >= HIGH
        recipientUserIds: [fakeSafetyManagerId],
      });

      assert.equal(sseSent, true);
      assert.equal(emailSent, true);
      assert.ok(result.channels.includes(NOTIFICATION_CHANNEL.IN_APP));
      assert.ok(result.channels.includes(NOTIFICATION_CHANNEL.EMAIL));
    });

    it("should respect disabled channel preference even if severity is CRITICAL", async () => {
      let emailSent = false;

      const mockRepo = {
        findUserPreferences: async () => [
          { channel: NOTIFICATION_CHANNEL.EMAIL, enabled: false, severityThreshold: NOTIFICATION_SEVERITY.LOW },
        ],
        createManyNotifications: async () => ({ count: 0 }),
      } as unknown as NotificationRepository;

      const mockUserRepo = {
        findActiveUsersByIds: async (ids: string[]) => [
          { id: ids[0], email: "officer@ppe.vn" },
        ],
      } as unknown as UserRepository;

      const mockMail = {
        sendPpeViolationAlertEmail: async () => {
          emailSent = true;
        },
      } as unknown as MailService;

      const service = new NotificationService(mockRepo, mockUserRepo, mockMail);

      const result = await service.dispatchIncidentNotification({
        incidentId: fakeIncidentId,
        violationType: "MULTI_VIOLATION",
        severity: "CRITICAL",
        recipientUserIds: [fakeSafetyOfficerId],
      });

      assert.equal(emailSent, false, "Email không được gửi vì người dùng đã tắt kênh EMAIL");
      assert.ok(!result.channels.includes(NOTIFICATION_CHANNEL.EMAIL));
    });
  });

  // ── 4. Incident Service Integration (BE-08 Acceptance Criteria) ───────────
  describe("4. Automatic Notification Dispatch from Incident Service", () => {
    it("should automatically dispatch PPE alert notification when Incident is created", async () => {
      let dispatchedIncidentId = "";
      let dispatchedSeverity = "";

      const mockIncidentRepo = {
        createIncident: async (data: any) => ({
          id: fakeIncidentId,
          siteId: data.siteId,
          cameraId: data.cameraId,
          violationType: data.violationType,
          severity: data.severity,
          description: data.description,
          detectedAt: new Date(),
        }),
      } as unknown as IncidentRepository;

      const mockNotificationService = {
        dispatchIncidentNotification: async (params: any) => {
          dispatchedIncidentId = params.incidentId;
          dispatchedSeverity = params.severity;
          return { incidentId: params.incidentId, dispatchedCount: 1, channels: ["IN_APP"] };
        },
      } as unknown as NotificationService;

      const incidentService = new IncidentService(
        mockIncidentRepo,
        undefined,
        mockNotificationService,
      );

      const created = await incidentService.createIncident(
        {
          siteId: fakeSiteId,
          cameraId: fakeCameraId,
          violationType: "NO_HELMET",
          severity: "HIGH",
          description: "Không đội mũ bảo hộ khu vực cẩu trục",
          detectedAt: new Date().toISOString(),
        },
        fakeSafetyOfficerId,
      );

      assert.equal(created.id, fakeIncidentId);

      // Đợi microtask chạy dispatch non-blocking
      await new Promise((resolve) => setTimeout(resolve, 30));

      assert.equal(dispatchedIncidentId, fakeIncidentId);
      assert.equal(dispatchedSeverity, "HIGH");
    });
  });

  // ── 5. User Notifications Inbox & Actions ──────────────────────────────────
  describe("5. User Notifications Inbox & Lifecycle Operations", () => {
    it("should list paginated notifications for current user", async () => {
      const mockRepo = {
        findMany: async (userId: string) => [
          [
            {
              id: fakeNotificationId,
              userId,
              title: "Cảnh báo vi phạm",
              content: "Phát hiện không đội mũ",
              severity: "HIGH",
              status: "SENT",
              createdAt: new Date(),
            },
          ],
          1,
          { page: 1, limit: 20, total: 1, totalPages: 1 },
        ],
      } as unknown as NotificationRepository;

      const service = new NotificationService(mockRepo);
      const res = await service.list(fakeSafetyOfficerId, { page: 1, limit: 20 });

      assert.equal(res.total, 1);
      assert.equal(res.items.length, 1);
      assert.equal(res.items[0].id, fakeNotificationId);
    });

    it("should retrieve unread notification count", async () => {
      const mockRepo = {
        countUnread: async () => 5,
      } as unknown as NotificationRepository;

      const service = new NotificationService(mockRepo);
      const res = await service.getUnreadCount(fakeSafetyOfficerId);

      assert.equal(res.unreadCount, 5);
    });

    it("should mark a specific notification as read and push SSE event", async () => {
      let sseEventPushed = false;
      let markedId = "";

      const mockRepo = {
        findOne: async (id: string, userId: string) => ({ id, userId }),
        markAsRead: async (id: string) => {
          markedId = id;
          return { count: 1 };
        },
      } as unknown as NotificationRepository;

      const mockSse = {
        sendToUser: (_userId: string, event: any) => {
          if (event.type === "notification:read") {
            sseEventPushed = true;
          }
        },
      } as unknown as SseManagerService;

      const service = new NotificationService(mockRepo, undefined, undefined, mockSse);
      await service.markAsRead(fakeSafetyOfficerId, fakeNotificationId);

      assert.equal(markedId, fakeNotificationId);
      assert.equal(sseEventPushed, true);
    });

    it("should throw 404 when marking non-existent notification as read", async () => {
      const mockRepo = {
        findOne: async () => null,
      } as unknown as NotificationRepository;

      const service = new NotificationService(mockRepo);

      await assert.rejects(
        async () => {
          await service.markAsRead(fakeSafetyOfficerId, fakeNotificationId);
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.equal(err.code, ERROR_CODE.NOT_FOUND);
          assert.equal(err.statusCode, 404);
          return true;
        },
      );
    });
  });

  // ── 6. SSE Stream Ticket & Security ────────────────────────────────────────
  describe("6. Realtime SSE Stream Ticket & Security Authentication", () => {
    it("should generate short-lived JWT stream ticket (60s) for authenticated user", () => {
      const service = new NotificationService();
      const ticketResult = service.createStreamTicket({
        id: fakeSafetyOfficerId,
        email: "officer@ppe.vn",
        role: "SAFETY_OFFICER",
      });

      assert.ok(ticketResult.ticket);
      assert.equal(ticketResult.expiresIn, 60);

      // Giải mã xác minh tính hợp lệ của ticket
      const decoded = jwt.verify(ticketResult.ticket, jwtConfig.tempSecret) as any;
      assert.equal(decoded.id, fakeSafetyOfficerId);
      assert.equal(decoded.purpose, JWT_PURPOSE.SSE_STREAM_TICKET);
    });

    it("should reject stream ticket creation when user is unauthenticated", () => {
      const service = new NotificationService();

      assert.throws(
        () => {
          service.createStreamTicket(undefined);
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.equal(err.code, ERROR_CODE.UNAUTHORIZED);
          assert.equal(err.statusCode, 401);
          return true;
        },
      );
    });
  });
});
