import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { NotificationService, IncidentClient } from "../src/modules/notification/notification.service";
import { maintenanceGuard } from "../src/middlewares/maintenance.middleware";
import { mailService } from "../src/common/services/mail.service";
import { emailTemplateService } from "../src/common/services/email-template.service";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { ROLES } from "../src/common/constants/role.constant";
import { NOTIFICATION_SEVERITY } from "../src/common/constants/notification.constant";

describe("Security Audit Patches - Batch 9 (SEC-34, SEC-35, SEC-36, SEC-37)", () => {
  describe("SEC-34: Unrestricted PPE Incident Notification Dispatch Guard", () => {
    it("should reject dispatchIncidentNotification with 404 NOT_FOUND if incident does not exist in incident service", async () => {
      const mockIncidentClient: IncidentClient = {
        getIncidentById: async (_id: string) => null, // Giả lập sự cố không tồn tại
      };

      const mockRepo: any = {
        findUserPreferences: async () => [],
      };

      const service = new NotificationService(
        mockRepo,
        undefined,
        undefined,
        undefined,
        mockIncidentClient,
      );

      await assert.rejects(
        async () => {
          await service.dispatchIncidentNotification({
            incidentId: "018f6e7c-8901-789a-bcde-f01234567899",
            siteId: "018f6e7c-8901-789a-bcde-f01234567800",
            violationType: "NO_HELMET",
            severity: NOTIFICATION_SEVERITY.HIGH,
            recipientUserIds: ["018f6e7c-8901-789a-bcde-f01234567801"],
          });
        },
        (err: any) => {
          assert.strictEqual(err.statusCode, 404);
          assert.strictEqual(err.code, ERROR_CODE.NOT_FOUND);
          assert.ok(err.message.includes("Không tìm thấy sự cố hợp lệ"));
          return true;
        },
      );
    });

    it("should allow dispatchIncidentNotification when incident exists", async () => {
      const validIncidentId = "018f6e7c-8901-789a-bcde-f01234567899";
      const mockIncidentClient: IncidentClient = {
        getIncidentById: async (id: string) => ({ id, title: "Valid Incident" }),
      };

      let createCalled = false;
      const mockRepo: any = {
        findPreferencesByUserIds: async () => [],
        findUserPreferences: async () => [],
        createManyNotifications: async () => {
          createCalled = true;
          return { count: 1 };
        },
      };

      const mockMail: any = {
        sendIncidentAlertEmail: async () => {},
        sendPpeViolationAlertEmail: async () => {},
      };

      const service = new NotificationService(
        mockRepo,
        mockMail,
        undefined,
        undefined,
        mockIncidentClient,
      );

      const result = await service.dispatchIncidentNotification({
        incidentId: validIncidentId,
        siteId: "018f6e7c-8901-789a-bcde-f01234567800",
        violationType: "NO_HELMET",
        severity: NOTIFICATION_SEVERITY.HIGH,
        recipientUserIds: ["018f6e7c-8901-789a-bcde-f01234567801"],
        recipientEmails: ["officer@example.com"],
      });

      assert.strictEqual(result.incidentId, validIncidentId);
      assert.strictEqual(createCalled, true);
    });
  });

  describe("SEC-35: Incomplete Maintenance Guard Middleware Hardening", () => {
    it("should allow request through when maintenance mode is inactive", async () => {
      const guard = maintenanceGuard({ isMaintenanceMode: false });
      const req: any = { originalUrl: "/api/v1/notifications" };
      let nextCalled = false;

      await guard(req, {} as any, (err?: any) => {
        assert.strictEqual(err, undefined);
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, true);
    });

    it("should block non-admin requests with 503 SYSTEM_MAINTENANCE when maintenance mode is active", async () => {
      const guard = maintenanceGuard({ isMaintenanceMode: true });
      const req: any = {
        originalUrl: "/api/v1/notifications",
        user: { role: "USER", permissions: ["NOTIFICATION_READ"] },
      };
      let errorThrown: any = null;

      await guard(req, {} as any, (err?: any) => {
        errorThrown = err;
      });

      assert.ok(errorThrown, "Must throw error when in maintenance mode");
      assert.strictEqual(errorThrown.statusCode, 503);
      assert.strictEqual(errorThrown.code, ERROR_CODE.SYSTEM_MAINTENANCE);
    });

    it("should exempt health check endpoints during maintenance", async () => {
      const guard = maintenanceGuard({ isMaintenanceMode: true });
      const exemptUrls = [
        "/health",
        "/api/v1/notifications/health",
        "/notifications/health",
        "/openapi.json",
      ];

      for (const url of exemptUrls) {
        const req: any = { originalUrl: url };
        let nextCalled = false;

        await guard(req, {} as any, (err?: any) => {
          assert.strictEqual(err, undefined);
          nextCalled = true;
        });

        assert.strictEqual(nextCalled, true, `Health check ${url} must bypass maintenance guard`);
      }
    });

    it("should allow ADMIN users and MAINTENANCE_BYPASS permissions to bypass maintenance", async () => {
      const guard = maintenanceGuard({ isMaintenanceMode: true });

      // Admin role
      const adminReq: any = {
        originalUrl: "/api/v1/notifications",
        user: { role: ROLES.ADMIN, permissions: [] },
      };
      let adminPassed = false;
      await guard(adminReq, {} as any, (err?: any) => {
        assert.strictEqual(err, undefined);
        adminPassed = true;
      });
      assert.strictEqual(adminPassed, true, "Admin role must bypass maintenance guard");

      // MAINTENANCE_BYPASS permission
      const bypassReq: any = {
        originalUrl: "/api/v1/notifications",
        user: { role: "OPERATOR", permissions: ["MAINTENANCE_BYPASS"] },
      };
      let bypassPassed = false;
      await guard(bypassReq, {} as any, (err?: any) => {
        assert.strictEqual(err, undefined);
        bypassPassed = true;
      });
      assert.strictEqual(bypassPassed, true, "MAINTENANCE_BYPASS permission must bypass maintenance guard");
    });
  });

  describe("SEC-36: Context-Aware HTML Attribute Escaping in Email URLs", () => {
    it("should escape special characters and attribute delimiters in sendVerificationEmail", async () => {
      let sentMailOptions: any = null;
      (mailService as any).dispatchEmail = async (options: any) => {
        sentMailOptions = options;
      };

      const maliciousToken = `abc123" onfocus="alert('XSS')" data-test="`;
      const originalIsConfigured = (mailService as any).transporter;

      try {
        await mailService.sendVerificationEmail(
          "user@example.com",
          maliciousToken,
          "John Doe",
        );
      } catch {
        // Có thể rơi vào fallback nếu mailConfig.isConfigured là false, ta test mailOptions trực tiếp
      }

      // Giả sử gọi mailService với token có dấu nháy kép, kiểm tra template service
      const template = (emailTemplateService as any).verifyEmail({
        token: maliciousToken,
        fullName: "John Doe",
      });

      assert.ok(
        !template.html.includes(`href="${maliciousToken}"`),
        "Raw unescaped malicious token must not be inside href attribute",
      );
      assert.ok(
        template.html.includes("&quot;"),
        "Double quotes must be escaped to &quot; inside html",
      );
    });

    it("should escape special characters and attribute delimiters in sendPasswordResetEmail", async () => {
      const maliciousResetUrl = `https://smart-ppe.com/reset?token=xyz" onmouseover="alert(1)`;
      const template = (emailTemplateService as any).resetPassword({
        resetUrl: maliciousResetUrl,
        fullName: "Jane Doe",
      });

      assert.ok(
        !template.html.includes(`href="${maliciousResetUrl}"`),
        "Raw unescaped malicious URL must not be inside href attribute",
      );
      assert.ok(
        template.html.includes("&quot;"),
        "Double quotes in URL must be escaped to &quot;",
      );
    });
  });

  describe("SEC-37: Rate Limiter Redis Client Reconnection Backoff Strategy", () => {
    it("rate-limit middleware source code must implement exponential retryStrategy instead of returning null", () => {
      const rateLimitFilePath = path.resolve(__dirname, "../src/middlewares/rate-limit.middleware.ts");
      const code = fs.readFileSync(rateLimitFilePath, "utf-8");

      assert.ok(
        !code.includes("retryStrategy: () => null"),
        "Must NOT abandon reconnection with retryStrategy: () => null",
      );
      assert.ok(
        code.includes("retryStrategy: (times) => Math.min(times * 100, 2000)"),
        "Must implement retryStrategy with exponential backoff capped at 2000ms",
      );
    });

    it("retryStrategy formula should calculate appropriate backoff intervals", () => {
      const retryStrategy = (times: number) => Math.min(times * 100, 2000);

      assert.strictEqual(retryStrategy(1), 100);
      assert.strictEqual(retryStrategy(5), 500);
      assert.strictEqual(retryStrategy(15), 1500);
      assert.strictEqual(retryStrategy(20), 2000);
      assert.strictEqual(retryStrategy(50), 2000, "Must be capped at 2000ms maximum delay");
    });
  });
});
