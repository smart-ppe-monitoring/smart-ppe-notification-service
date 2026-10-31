import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { NotificationRepository } from "../src/modules/notification/notification.repository";
import {
  authMiddleware,
  extractTokenFromRequest,
  isStreamEndpoint,
} from "../src/middlewares/auth.middleware";
import { NOTIFICATION_STATUS, NOTIFICATION_SEVERITY } from "../src/common/constants/notification.constant";
import { ERROR_CODE } from "../src/common/errors/error-code";

describe("Security Audit Patches - Batch 10 (SEC-38, SEC-39, SEC-40, SEC-41)", () => {
  describe("SEC-38: Inbox Notification Search and Type Query Filtering", () => {
    it("findMany should integrate search filter into Prisma where clause with case-insensitive title and content", async () => {
      let capturedWhere: any = null;

      const mockDb: any = {
        notification: {
          findMany: async (args: any) => {
            capturedWhere = args.where;
            return [];
          },
          count: async () => 0,
        },
      };

      const repo = new NotificationRepository();
      (repo as any).db = mockDb;

      const userId = "018f6e7c-8901-789a-bcde-f0123456789a";
      await repo.findMany(userId, {
        search: "mũ bảo hộ",
      });

      assert.ok(capturedWhere, "where clause must be passed to Prisma findMany");
      assert.ok(capturedWhere.AND, "where.AND must exist to preserve user isolation and soft delete");

      const searchCondition = capturedWhere.AND.find((cond: any) => cond.OR && cond.OR.some((sub: any) => sub.title));
      assert.ok(searchCondition, "Must contain OR condition for title and content search");
      assert.deepStrictEqual(searchCondition.OR, [
        { title: { contains: "mũ bảo hộ", mode: "insensitive" } },
        { content: { contains: "mũ bảo hộ", mode: "insensitive" } },
      ]);
    });

    it("findMany should filter by type (ALERT / NOTIFICATION / template code)", async () => {
      let capturedWhereAlert: any = null;
      let capturedWhereNotif: any = null;

      const mockDb: any = {
        notification: {
          findMany: async (args: any) => {
            if (!capturedWhereAlert) {
              capturedWhereAlert = args.where;
            } else {
              capturedWhereNotif = args.where;
            }
            return [];
          },
          count: async () => 0,
        },
      };

      const repo = new NotificationRepository();
      (repo as any).db = mockDb;
      const userId = "018f6e7c-8901-789a-bcde-f0123456789a";

      // Test type: ALERT
      await repo.findMany(userId, { type: "ALERT" });
      const alertCondition = capturedWhereAlert.AND.find((c: any) => c.severity);
      assert.ok(alertCondition, "Must include severity filter for type ALERT");
      assert.deepStrictEqual(alertCondition.severity, {
        in: [NOTIFICATION_SEVERITY.HIGH, NOTIFICATION_SEVERITY.CRITICAL],
      });

      // Test type: NOTIFICATION
      await repo.findMany(userId, { type: "NOTIFICATION" });
      const notifCondition = capturedWhereNotif.AND.find((c: any) => c.severity);
      assert.ok(notifCondition, "Must include severity filter for type NOTIFICATION");
      assert.deepStrictEqual(notifCondition.severity, {
        in: [NOTIFICATION_SEVERITY.LOW, NOTIFICATION_SEVERITY.NORMAL, NOTIFICATION_SEVERITY.MEDIUM],
      });
    });
  });

  describe("SEC-39: Query Token Leakage Guard on Unintended Routes", () => {
    it("should accept query token only on exact stream routes", () => {
      const validStreamRoutes = [
        { originalUrl: "/api/v1/notifications/stream", path: "/stream", baseUrl: "/api/v1/notifications" },
        { originalUrl: "/notifications/stream", path: "/stream", baseUrl: "/notifications" },
        { originalUrl: "/stream", path: "/stream", baseUrl: "" },
      ];

      for (const route of validStreamRoutes) {
        const req: any = {
          ...route,
          headers: {},
          query: { token: "valid-sse-stream-token" },
        };
        assert.strictEqual(
          isStreamEndpoint(req),
          true,
          `Expected ${route.originalUrl} to be recognized as stream endpoint`,
        );
        const token = extractTokenFromRequest(req);
        assert.strictEqual(token, "valid-sse-stream-token");
      }
    });

    it("should reject query token on routes ending with /stream that are NOT stream endpoints (e.g. /templates/stream)", async () => {
      const maliciousReq: any = {
        originalUrl: "/api/v1/notifications/templates/stream",
        path: "/templates/stream",
        baseUrl: "/api/v1/notifications",
        headers: {},
        query: { token: "leaked-token-in-query" },
      };

      assert.strictEqual(
        isStreamEndpoint(maliciousReq),
        false,
        "/templates/stream must NOT be classified as stream endpoint",
      );

      const extractedToken = extractTokenFromRequest(maliciousReq);
      assert.strictEqual(
        extractedToken,
        undefined,
        "extractTokenFromRequest must ignore query token for /templates/stream",
      );

      let errorThrown: any = null;
      await authMiddleware(maliciousReq, {} as any, (err?: any) => {
        errorThrown = err;
      });

      assert.ok(errorThrown, "Must throw error when query token is passed to regular API");
      assert.strictEqual(errorThrown.statusCode, 400);
      assert.strictEqual(errorThrown.code, ERROR_CODE.VALIDATION_ERROR);
    });
  });

  describe("SEC-40: Status Corruption on Mark All As Read Prevention", () => {
    it("markAllAsRead should only update notifications with status in ['SENT', 'DELIVERED']", async () => {
      let capturedWhere: any = null;
      let capturedData: any = null;

      const mockDb: any = {
        notification: {
          updateMany: async (args: any) => {
            capturedWhere = args.where;
            capturedData = args.data;
            return { count: 3 };
          },
        },
      };

      const repo = new NotificationRepository();
      (repo as any).db = mockDb;

      const testUserId = "018f6e7c-8901-789a-bcde-f0123456789b";
      await repo.markAllAsRead(testUserId);

      assert.ok(capturedWhere, "Must call updateMany with where condition");
      assert.strictEqual(capturedWhere.userId, testUserId);
      assert.strictEqual(capturedWhere.deletedAt, null);
      assert.deepStrictEqual(
        capturedWhere.status,
        { in: [NOTIFICATION_STATUS.SENT, "DELIVERED"] },
        "Must NOT match FAILED or PENDING statuses",
      );

      assert.strictEqual(capturedData.status, NOTIFICATION_STATUS.READ);
      assert.ok(capturedData.readAt instanceof Date);
    });
  });

  describe("SEC-41: Soft Delete & Prevention of Cascade Hard Deletion of Audit Logs", () => {
    it("delete should perform soft delete setting deletedAt instead of hard deleting records", async () => {
      let updateArgs: any = null;
      let deleteCalled = false;

      const mockDb: any = {
        notification: {
          updateMany: async (args: any) => {
            updateArgs = args;
            return { count: 1 };
          },
          deleteMany: async () => {
            deleteCalled = true;
            return { count: 0 };
          },
        },
      };

      const repo = new NotificationRepository();
      (repo as any).db = mockDb;

      const testId = "018f6e7c-8901-789a-bcde-f0123456789c";
      const testUserId = "018f6e7c-8901-789a-bcde-f0123456789d";

      await repo.delete(testId, testUserId);

      assert.strictEqual(deleteCalled, false, "Hard delete (deleteMany) must NOT be called");
      assert.ok(updateArgs, "Soft delete (updateMany) must be called");
      assert.strictEqual(updateArgs.where.id, testId);
      assert.strictEqual(updateArgs.where.userId, testUserId);
      assert.strictEqual(updateArgs.where.deletedAt, null);
      assert.ok(updateArgs.data.deletedAt instanceof Date, "Must set deletedAt timestamp");
    });

    it("schema.prisma must define deletedAt on Notification and onDelete: Restrict on NotificationLog", () => {
      const schemaPath = path.resolve(__dirname, "../prisma/schema.prisma");
      const schema = fs.readFileSync(schemaPath, "utf-8");

      assert.ok(
        schema.includes('deletedAt  DateTime? @map("deleted_at")'),
        "Notification model must define deletedAt field",
      );
      assert.ok(
        schema.includes("onDelete: Restrict"),
        "NotificationLog relation must use onDelete: Restrict instead of Cascade",
      );
    });
  });
});
