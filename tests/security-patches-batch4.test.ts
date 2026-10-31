import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { mailConfig } from "../src/config/mail.config";
import { envConfig } from "../src/config/env.config";
import { resolveSatellitePermissions, requirePermission } from "../src/middlewares/permission.middleware";
import { EmailTemplateService } from "../src/common/services/email-template.service";
import { NotificationService } from "../src/modules/notification/notification.service";
import { MailService } from "../src/common/services/mail.service";
import { ROLES } from "../src/common/constants/role.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import {
  NOTIFICATION_CHANNEL,
  NOTIFICATION_SEVERITY,
  SYSTEM_BROADCAST_USER_ID,
} from "../src/common/constants/notification.constant";

describe("Security Audit Patches - Batch 4 (SEC-12, SEC-13, SEC-14, SEC-15, SEC-16)", () => {
  describe("SEC-12: Dockerfile Missing Keys, Lockfile and Port Hardening", () => {
    it("should include pnpm-lock.yaml in deps stage", () => {
      const dockerfilePath = path.resolve(__dirname, "../Dockerfile");
      const dockerfileContent = fs.readFileSync(dockerfilePath, "utf8");
      assert.match(
        dockerfileContent,
        /COPY package\.json pnpm-lock\.yaml \.\//,
        "Dockerfile must copy pnpm-lock.yaml to guarantee deterministic dependencies",
      );
    });

    it("should copy keys directory to runner stage for offline RS256 token verification", () => {
      const dockerfilePath = path.resolve(__dirname, "../Dockerfile");
      const dockerfileContent = fs.readFileSync(dockerfilePath, "utf8");
      assert.match(
        dockerfileContent,
        /COPY --from=builder \/app\/keys \.\/keys/,
        "Dockerfile runner stage must copy keys directory",
      );
    });

    it("should expose port 8894 matching Notification Service port configuration", () => {
      const dockerfilePath = path.resolve(__dirname, "../Dockerfile");
      const dockerfileContent = fs.readFileSync(dockerfilePath, "utf8");
      assert.match(
        dockerfileContent,
        /EXPOSE 8894/,
        "Dockerfile must expose port 8894 for Notification Service",
      );
    });
  });

  describe("SEC-13: Tier-2 Email Webhook Relay HMAC Signature & Authentication", () => {
    it("should include X-Webhook-Signature and Authorization headers when dispatching via webhook", async () => {
      const mailService = new MailService();

      let interceptedUrl = "";
      let interceptedHeaders: any = {};
      let interceptedBody = "";

      const origFetch = global.fetch;
      (global as any).fetch = async (url: string, init: any) => {
        interceptedUrl = url;
        interceptedHeaders = init.headers;
        interceptedBody = init.body;
        return {
          ok: true,
          status: 200,
          text: async () => "OK",
        };
      };

      try {
        await (mailService as any).sendViaWebhook({
          to: "receiver@smart-ppe.local",
          subject: "Test Webhook Subject",
          html: "<p>Test Content</p>",
        });
      } finally {
        global.fetch = origFetch;
      }

      assert.ok(interceptedHeaders["X-Webhook-Signature"]);
      assert.ok(interceptedHeaders["X-Webhook-Timestamp"]);
      assert.match(interceptedHeaders["Authorization"], /^Bearer\s+/);

      // Verify the HMAC-SHA256 signature matches the payload
      const webhookSecret =
        mailConfig.webhookSecret ||
        envConfig.gateway.internalSecret ||
        envConfig.encryption.key;

      const expectedHmac = crypto
        .createHmac("sha256", webhookSecret)
        .update(interceptedBody)
        .digest("hex");

      assert.equal(interceptedHeaders["X-Webhook-Signature"], expectedHmac);
    });
  });

  describe("SEC-14: Explicit Empty Permissions Array Revocation Defense", () => {
    it("should strictly respect permissions: [] and NOT escalate to Admin default permissions", () => {
      const req: any = {
        user: {
          id: "usr-revoked-admin",
          role: ROLES.ADMIN,
          permissions: [], // Explicitly revoked!
        },
      };

      const perms = resolveSatellitePermissions(req);
      assert.equal(perms.size, 0, "Revoked user with permissions: [] must have 0 permissions");

      // Attempting to access protected resource with requirePermission must fail
      const middleware = requirePermission(PERMISSIONS.NOTIFICATION_CREATE);
      let errorThrown: any = null;
      let nextCalled = false;

      middleware(req, {} as any, (err?: any) => {
        if (err) errorThrown = err;
        else nextCalled = true;
      });

      assert.equal(nextCalled, false);
      assert.ok(errorThrown);
      assert.equal(errorThrown.statusCode, 403);
    });

    it("should strictly respect permissions: [] and NOT escalate to Safety Manager default permissions", () => {
      const req: any = {
        user: {
          id: "usr-revoked-manager",
          role: ROLES.SAFETY_MANAGER,
          permissions: [], // Explicitly revoked!
        },
      };

      const perms = resolveSatellitePermissions(req);
      assert.equal(perms.size, 0, "Revoked safety manager must have 0 permissions");
    });

    it("should fall back to default role permissions when user.permissions is undefined (standard legacy token)", () => {
      const req: any = {
        user: {
          id: "usr-legacy-admin",
          role: ROLES.ADMIN,
          permissions: undefined, // Standard token without explicit permissions array
        },
      };

      const perms = resolveSatellitePermissions(req);
      assert.ok(perms.size > 0);
      assert.ok(perms.has(PERMISSIONS.NOTIFICATION_CREATE));
    });
  });

  describe("SEC-15: System-Wide Broadcast Endpoint Database Persistence", () => {
    it("should persist broadcast announcements to PostgreSQL database and push via SSE", async () => {
      let createdRecords: any[] = [];
      let sseBroadcastCalled = false;
      let sseEventPayload: any = null;

      const mockRepository: any = {
        findDistinctUserIds: async () => [
          "018f6e7c-8901-789a-bcde-f0123456789a",
          "018f6e7c-8901-789a-bcde-f0123456789b",
        ],
        createManyNotifications: async (records: any[]) => {
          createdRecords = records;
          return { count: records.length };
        },
      };

      const mockSse: any = {
        broadcast: (event: any) => {
          sseBroadcastCalled = true;
          sseEventPayload = event;
        },
      };

      const service = new NotificationService(mockRepository, {} as any, mockSse);

      const result = await service.broadcast({
        title: "Khẩn cấp: Bão sắp đổ bộ công trường",
        content: "Yêu cầu toàn bộ công nhân di tản khỏi khu vực cần cẩu",
        severity: NOTIFICATION_SEVERITY.CRITICAL,
      });

      // Verify database persistence occurred
      assert.ok(createdRecords.length >= 2, "Broadcast must persist records in database");
      assert.equal(
        createdRecords.some((r) => r.userId === "018f6e7c-8901-789a-bcde-f0123456789a"),
        true,
      );
      assert.equal(
        createdRecords.some((r) => r.userId === SYSTEM_BROADCAST_USER_ID),
        true,
        "Must include SYSTEM_BROADCAST_USER_ID for future/offline users",
      );

      // Verify SSE real-time broadcast occurred
      assert.equal(sseBroadcastCalled, true);
      assert.equal(sseEventPayload.type, "notification:broadcast");
      assert.match(sseEventPayload.data.title, /Khẩn cấp/);

      assert.equal(result.totalRecipients, 2);
    });
  });

  describe("SEC-16: Stored HTML Injection in Email Template Rendering", () => {
    it("should sanitize and escape malicious HTML tags in title inside baseLayout", () => {
      const templateService = new EmailTemplateService();

      const maliciousTitle = '<script>alert("XSS")</script><img src="x" onerror="stealCookie()">Thông báo an toàn';
      const safeBody = "<p>Nội dung thông báo</p>";

      const renderedHtml = templateService.baseLayout(maliciousTitle, safeBody);

      // Malicious tags must NOT be present unescaped
      assert.equal(renderedHtml.includes("<script>"), false);
      assert.equal(renderedHtml.includes('<img src="x" onerror="stealCookie()">'), false);

      // Escaped entities must be present
      assert.ok(renderedHtml.includes("&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;"));
      assert.ok(renderedHtml.includes("&lt;img src=&quot;x&quot; onerror=&quot;stealCookie()&quot;&gt;"));
      assert.ok(renderedHtml.includes("Thông báo an toàn"));
    });
  });
});
