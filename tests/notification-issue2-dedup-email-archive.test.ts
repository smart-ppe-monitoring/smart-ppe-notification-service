import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import jwt from "jsonwebtoken";
import notificationApp from "../src/notification.app";
import notificationRoute from "../src/modules/notification/notification.route";
import { notificationPrisma } from "../src/database/notification.client";
import { jwtConfig } from "../src/config/jwt.config";
import { envConfig } from "../src/config/env.config";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { ROLES } from "../src/common/constants/role.constant";
import {
  NOTIFICATION_CHANNEL,
  INBOX_NOTIFICATION_CHANNELS,
  NOTIFICATION_SEVERITY,
  NOTIFICATION_STATUS,
  EMAIL_STATUS,
  SYSTEM_BROADCAST_USER_ID,
} from "../src/common/constants/notification.constant";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { AppError } from "../src/common/errors/app-error";
import {
  listEmailsSchema,
  listNotificationsSchema,
} from "../src/modules/notification/notification.validation";
import { NotificationRepository } from "../src/modules/notification/notification.repository";
import { NotificationService } from "../src/modules/notification/notification.service";
import { buildOpenApiSpec } from "../src/config/openapi/openapi.registry";
import { registerNotificationOpenApi } from "../src/modules/notification/notification.openapi";

describe("Issue #2: Broadcast & Multi-Channel Dedup, Email Date Filters, Permissions & Archive", () => {
  const userA = "018f0000-0000-7000-8000-000000000a01";
  const userB = "018f0000-0000-7000-8000-000000000a02";
  const incident1 = "018f0000-0000-7000-8000-000000000b01";
  const notif1 = "018f0000-0000-7000-8000-000000000c01";

  describe("1. Zod Validation (listEmailsSchema & listNotificationsSchema)", () => {
    it("listEmailsSchema should accept ISO 8601, YYYY-MM-DD, and DD/MM/YYYY for fromDate and toDate", () => {
      const isoParsed = listEmailsSchema.parse({
        fromDate: "2026-11-01T00:00:00.000Z",
        toDate: "2026-11-26T23:59:59.999Z",
      });
      assert.strictEqual(isoParsed.fromDate, "2026-11-01T00:00:00.000Z");
      assert.strictEqual(isoParsed.toDate, "2026-11-26T23:59:59.999Z");

      const ymdParsed = listEmailsSchema.parse({
        fromDate: "2026-11-01",
        toDate: "2026-11-26",
      });
      assert.strictEqual(ymdParsed.fromDate, "2026-11-01");
      assert.strictEqual(ymdParsed.toDate, "2026-11-26");

      const vnParsed = listEmailsSchema.parse({
        fromDate: "01/11/2026",
        toDate: "26/11/2026",
      });
      assert.strictEqual(vnParsed.fromDate, "01/11/2026");
      assert.strictEqual(vnParsed.toDate, "26/11/2026");
    });

    it("listEmailsSchema should reject invalid date strings and fromDate > toDate", () => {
      assert.throws(() => listEmailsSchema.parse({ fromDate: "not-a-date" }));
      assert.throws(() => listEmailsSchema.parse({ toDate: "31/02/2026" }));
      assert.throws(() =>
        listEmailsSchema.parse({
          fromDate: "2026-11-26",
          toDate: "2026-11-01",
        }),
      );
    });

    it("listNotificationsSchema should parse archived='true'|'false' and reject invalid values", () => {
      assert.strictEqual(listNotificationsSchema.parse({}).archived, undefined);
      assert.strictEqual(
        listNotificationsSchema.parse({ archived: "true" }).archived,
        true,
      );
      assert.strictEqual(
        listNotificationsSchema.parse({ archived: "false" }).archived,
        false,
      );
      assert.throws(() => listNotificationsSchema.parse({ archived: "yes" }));
    });
  });

  describe("2. Broadcast Deduplication (Unit)", () => {
    it("should create exactly 1 record per distinct user and exclude SYSTEM_BROADCAST_USER_ID", async () => {
      let persisted: any[] = [];
      const mockRepo: any = {
        findDistinctUserIds: async () => [userA, userB, userA, SYSTEM_BROADCAST_USER_ID],
        createManyNotifications: async (records: any[]) => {
          persisted = records;
          return { count: records.length };
        },
      };
      const mockSse: any = { broadcast: () => {} };
      const service = new NotificationService(mockRepo, {} as any, mockSse);

      const res = await service.broadcast({
        title: "System Maintenance",
        content: "Maintenance at 23:00",
        severity: NOTIFICATION_SEVERITY.HIGH,
      });

      assert.strictEqual(res.totalRecipients, 2);
      assert.strictEqual(persisted.length, 2);
      assert.deepStrictEqual(
        persisted.map((r) => r.userId).sort(),
        [userA, userB].sort(),
      );
      assert.strictEqual(
        persisted.some((r) => r.userId === SYSTEM_BROADCAST_USER_ID),
        false,
      );
    });

    it("should fallback to SYSTEM_BROADCAST_USER_ID only when no distinct user exists", async () => {
      let persisted: any[] = [];
      const mockRepo: any = {
        findDistinctUserIds: async () => [],
        createManyNotifications: async (records: any[]) => {
          persisted = records;
          return { count: records.length };
        },
      };
      const mockSse: any = { broadcast: () => {} };
      const service = new NotificationService(mockRepo, {} as any, mockSse);

      const res = await service.broadcast({
        title: "Welcome",
        content: "Initial broadcast",
      });

      assert.strictEqual(res.totalRecipients, 1);
      assert.strictEqual(persisted.length, 1);
      assert.strictEqual(persisted[0].userId, SYSTEM_BROADCAST_USER_ID);
    });
  });

  describe("3. Multi-Channel Inbox Deduplication, deliveredChannels & Archive Filters (Repository Unit)", () => {
    it("findMany should strictly filter by userId, archivedAt: null, INBOX_NOTIFICATION_CHANNELS, and enrich deliveredChannels", async () => {
      const capturedFindManyArgs: any[] = [];
      let capturedCountArgs: any = null;
      const now = new Date();

      const mockDb: any = {
        notification: {
          findMany: async (args: any) => {
            capturedFindManyArgs.push(args);
            if (capturedFindManyArgs.length === 1) {
              return [
                {
                  id: notif1,
                  userId: userA,
                  incidentId: incident1,
                  templateId: null,
                  channel: NOTIFICATION_CHANNEL.IN_APP,
                  title: "Vi phạm PPE",
                  content: "Không đội mũ",
                  severity: NOTIFICATION_SEVERITY.HIGH,
                  status: NOTIFICATION_STATUS.SENT,
                  sentAt: now,
                  readAt: null,
                  archivedAt: null,
                  createdAt: now,
                },
              ];
            }
            return [
              {
                incidentId: incident1,
                title: "Vi phạm PPE",
                channel: NOTIFICATION_CHANNEL.EMAIL,
                createdAt: now,
              },
            ];
          },
          count: async (args: any) => {
            capturedCountArgs = args;
            return 1;
          },
        },
      };

      const repo = new NotificationRepository();
      (repo as any).db = mockDb;

      const [items, total] = await repo.findMany(userA, { page: 1, limit: 20 });

      assert.strictEqual(total, 1);
      assert.strictEqual(items.length, 1);
      assert.deepStrictEqual(items[0].deliveredChannels, [
        NOTIFICATION_CHANNEL.IN_APP,
        NOTIFICATION_CHANNEL.EMAIL,
      ]);
      assert.strictEqual(items[0].archivedAt, null);

      const inboxWhere = capturedFindManyArgs[0].where;
      assert.deepStrictEqual(inboxWhere.channel, {
        in: [...INBOX_NOTIFICATION_CHANNELS],
      });
      assert.deepStrictEqual(inboxWhere.AND[0], { userId: userA });
      assert.deepStrictEqual(inboxWhere.AND[1], { deletedAt: null });
      assert.deepStrictEqual(inboxWhere.AND[2], { archivedAt: null });
      assert.deepStrictEqual(capturedCountArgs.where, inboxWhere);
    });

    it("findMany should honor explicit channel='EMAIL' and archived=true without sibling lookup", async () => {
      const capturedFindManyArgs: any[] = [];
      const mockDb: any = {
        notification: {
          findMany: async (args: any) => {
            capturedFindManyArgs.push(args);
            return [];
          },
          count: async () => 0,
        },
      };

      const repo = new NotificationRepository();
      (repo as any).db = mockDb;

      await repo.findMany(userA, {
        channel: NOTIFICATION_CHANNEL.EMAIL,
        archived: true,
      });

      assert.strictEqual(capturedFindManyArgs.length, 1);
      assert.strictEqual(
        capturedFindManyArgs[0].where.channel,
        NOTIFICATION_CHANNEL.EMAIL,
      );
      assert.deepStrictEqual(capturedFindManyArgs[0].where.AND[2], {
        archivedAt: { not: null },
      });
    });

    it("countUnread and markAllAsRead should scope to INBOX_NOTIFICATION_CHANNELS and archivedAt: null", async () => {
      let countWhere: any = null;
      let updateWhere: any = null;
      const mockDb: any = {
        notification: {
          count: async (args: any) => {
            countWhere = args.where;
            return 2;
          },
          updateMany: async (args: any) => {
            updateWhere = args.where;
            return { count: 2 };
          },
        },
      };

      const repo = new NotificationRepository();
      (repo as any).db = mockDb;

      const unread = await repo.countUnread(userA);
      assert.strictEqual(unread, 2);
      assert.strictEqual(countWhere.userId, userA);
      assert.strictEqual(countWhere.deletedAt, null);
      assert.strictEqual(countWhere.archivedAt, null);
      assert.deepStrictEqual(countWhere.channel, {
        in: [...INBOX_NOTIFICATION_CHANNELS],
      });

      await repo.markAllAsRead(userA);
      assert.strictEqual(updateWhere.userId, userA);
      assert.strictEqual(updateWhere.deletedAt, null);
      assert.strictEqual(updateWhere.archivedAt, null);
      assert.deepStrictEqual(updateWhere.channel, {
        in: [...INBOX_NOTIFICATION_CHANNELS],
      });
    });
  });

  describe("4. Email Logs Date Filtering & Unified /emails Permissions", () => {
    it("findEmails should apply Vietnam day boundaries for DD/MM/YYYY / YYYY-MM-DD fromDate & toDate", async () => {
      let capturedWhere: any = null;
      const mockDb: any = {
        emailNotification: {
          findMany: async (args: any) => {
            capturedWhere = args.where;
            return [];
          },
          count: async () => 0,
        },
      };

      const repo = new NotificationRepository();
      (repo as any).db = mockDb;

      await repo.findEmails({
        fromDate: "01/11/2026",
        toDate: "26/11/2026",
        status: EMAIL_STATUS.FAILED,
      });

      assert.strictEqual(capturedWhere.status, EMAIL_STATUS.FAILED);
      assert.ok(capturedWhere.createdAt.gte instanceof Date);
      assert.ok(capturedWhere.createdAt.lte instanceof Date);
      assert.strictEqual(
        capturedWhere.createdAt.gte.toISOString(),
        "2026-10-31T17:00:00.000Z",
      );
      assert.strictEqual(
        capturedWhere.createdAt.lte.toISOString(),
        "2026-11-26T16:59:59.999Z",
      );
    });

    it("GET /emails and POST /emails/:id/retry should both allow NOTIFICATION_TEMPLATE_MANAGE or NOTIFICATION_UPDATE and block NOTIFICATION_READ-only", async () => {
      const stack = (notificationRoute as any).stack || [];
      const getEmailsLayer = stack.find(
        (l: any) => l.route?.path === "/emails" && l.route?.methods?.get,
      );
      const retryEmailLayer = stack.find(
        (l: any) =>
          l.route?.path === "/emails/:id/retry" && l.route?.methods?.post,
      );

      assert.ok(getEmailsLayer, "GET /emails route must exist");
      assert.ok(retryEmailLayer, "POST /emails/:id/retry route must exist");

      const getPermMw = getEmailsLayer.route.stack[0].handle;
      const retryPermMw = retryEmailLayer.route.stack[0].handle;

      const testPerm = (mw: any, permissions: string[]) =>
        new Promise<number>((resolve) => {
          const req: any = {
            user: { id: userA, role: ROLES.SAFETY_MANAGER, permissions },
          };
          mw(req, {} as any, (err?: any) => {
            resolve(err ? err.statusCode : 200);
          });
        });

      for (const mw of [getPermMw, retryPermMw]) {
        assert.strictEqual(
          await testPerm(mw, [PERMISSIONS.NOTIFICATION_TEMPLATE_MANAGE]),
          200,
        );
        assert.strictEqual(
          await testPerm(mw, [PERMISSIONS.NOTIFICATION_UPDATE]),
          200,
        );
        assert.strictEqual(
          await testPerm(mw, [PERMISSIONS.NOTIFICATION_READ]),
          403,
        );
      }
    });
  });

  describe("5. Archive Service Unit Tests", () => {
    it("should archive, unarchive, archiveAllRead, and throw 404 when notification is not found", async () => {
      let archivedId = "";
      let unarchivedId = "";
      const mockRepo: any = {
        findOne: async (id: string, uid: string) =>
          id === notif1 && uid === userA ? { id, userId: uid } : null,
        archive: async (id: string) => {
          archivedId = id;
          return { count: 1 };
        },
        unarchive: async (id: string) => {
          unarchivedId = id;
          return { count: 1 };
        },
        archiveAllRead: async () => ({ count: 4 }),
      };

      const service = new NotificationService(mockRepo);
      await service.archive(userA, notif1);
      assert.strictEqual(archivedId, notif1);

      await service.unarchive(userA, notif1);
      assert.strictEqual(unarchivedId, notif1);

      const batch = await service.archiveAllRead(userA);
      assert.deepStrictEqual(batch, { archivedCount: 4 });

      await assert.rejects(
        () => service.archive(userB, notif1),
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 404);
          assert.strictEqual(err.code, ERROR_CODE.NOT_FOUND);
          return true;
        },
      );
    });
  });

  describe("6. OpenAPI Specification", () => {
    it("should document archived, deliveredChannels, archive endpoints, and email fromDate/toDate filters", () => {
      registerNotificationOpenApi();
      const spec = buildOpenApiSpec();

      const getNotifs = spec.paths?.["/notifications"]?.get;
      assert.ok(getNotifs);
      assert.ok(
        (getNotifs.parameters || []).some((p: any) => p.name === "archived"),
      );

      assert.ok(spec.paths?.["/notifications/archive-read"]?.patch);
      assert.ok(spec.paths?.["/notifications/{id}/archive"]?.patch);
      assert.ok(spec.paths?.["/notifications/{id}/unarchive"]?.patch);

      const getEmails = spec.paths?.["/notifications/emails"]?.get;
      assert.ok(getEmails);
      const emailParams: any[] = getEmails.parameters || [];
      assert.ok(emailParams.some((p) => p.name === "fromDate"));
      assert.ok(emailParams.some((p) => p.name === "toDate"));
    });
  });

  describe("7. Live HTTP + PostgreSQL (ppe_notification_db) Integration Tests", () => {
    let server: http.Server | null = null;
    let baseUrl = "";
    let dbAvailable = false;
    let origPublicKey = "";
    let testPrivateKey = "";

    const liveUserA = crypto.randomUUID();
    const liveUserB = crypto.randomUUID();
    const liveIncidentId = crypto.randomUUID();
    const broadcastTitle = `IT Broadcast ${crypto.randomBytes(4).toString("hex")}`;
    const emailTag = crypto.randomBytes(4).toString("hex");

    const createdNotificationIds: string[] = [];
    const createdEmailIds: string[] = [];
    const createdPrefUsers: string[] = [];

    function signToken(
      userId: string,
      role: string,
      permissions: string[],
    ): string {
      return jwt.sign(
        {
          id: userId,
          email: `${userId}@smartppe.local`,
          role,
          roleId: crypto.randomUUID(),
          permissions,
          purpose: JWT_PURPOSE.ACCESS,
          mustChangePassword: false,
        },
        testPrivateKey,
        { algorithm: "RS256", expiresIn: "15m" },
      );
    }

    async function requestJson(
      method: string,
      path: string,
      token: string,
      body?: unknown,
    ) {
      const headers: Record<string, string> = {
        authorization: `Bearer ${token}`,
      };
      if (envConfig.gateway.internalSecret) {
        headers[GATEWAY_HEADERS.INTERNAL_SECRET] =
          envConfig.gateway.internalSecret;
      }
      if (body !== undefined) {
        headers["content-type"] = "application/json";
      }
      const res = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
      const text = await res.text();
      return {
        status: res.status,
        body: text ? JSON.parse(text) : null,
      };
    }

    before(async () => {
      try {
        await notificationPrisma.$queryRaw`SELECT 1`;
        dbAvailable = true;
      } catch {
        dbAvailable = false;
        return;
      }

      origPublicKey = jwtConfig.publicKey;
      const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      testPrivateKey = privateKey;
      jwtConfig.publicKey = publicKey;

      // Seed preferences for liveUserA & liveUserB so findDistinctUserIds() discovers both
      await notificationPrisma.notificationPreference.createMany({
        data: [
          {
            userId: liveUserA,
            channel: NOTIFICATION_CHANNEL.IN_APP,
            enabled: true,
            severityThreshold: NOTIFICATION_SEVERITY.LOW,
          },
          {
            userId: liveUserB,
            channel: NOTIFICATION_CHANNEL.IN_APP,
            enabled: true,
            severityThreshold: NOTIFICATION_SEVERITY.LOW,
          },
        ],
      });
      createdPrefUsers.push(liveUserA, liveUserB);

      server = await new Promise<http.Server>((resolve) => {
        const s = notificationApp.listen(0, "127.0.0.1", () => resolve(s));
      });
      const addr = server.address() as AddressInfo;
      baseUrl = `http://127.0.0.1:${addr.port}`;
    });

    after(async () => {
      if (origPublicKey) {
        jwtConfig.publicKey = origPublicKey;
      }
      if (dbAvailable) {
        const broadcastRows = await notificationPrisma.notification
          .findMany({
            where: { title: broadcastTitle },
            select: { id: true },
          })
          .catch(() => []);
        const allNotifIds = Array.from(
          new Set([
            ...createdNotificationIds,
            ...broadcastRows.map((r) => r.id),
          ]),
        );

        if (allNotifIds.length > 0) {
          await notificationPrisma.notificationLog
            .deleteMany({ where: { notificationId: { in: allNotifIds } } })
            .catch(() => {});
          await notificationPrisma.notification
            .deleteMany({ where: { id: { in: allNotifIds } } })
            .catch(() => {});
        }
        if (createdEmailIds.length > 0) {
          await (notificationPrisma as any).emailNotification
            .deleteMany({ where: { id: { in: createdEmailIds } } })
            .catch(() => {});
        }
        if (createdPrefUsers.length > 0) {
          await notificationPrisma.notificationPreference
            .deleteMany({ where: { userId: { in: createdPrefUsers } } })
            .catch(() => {});
        }
      }
      if (server) {
        await new Promise<void>((resolve) => {
          server!.close(() => resolve());
        });
      }
      await notificationPrisma.$disconnect().catch(() => {});
    });

    it("Broadcast should create 1 row per user with no SYSTEM_BROADCAST_USER_ID duplicate and allow independent markAsRead & delete", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_notification_db is unavailable");
        return;
      }

      const adminToken = signToken(liveUserA, ROLES.ADMIN, [
        PERMISSIONS.NOTIFICATION_CREATE,
        PERMISSIONS.NOTIFICATION_READ,
      ]);
      const userAToken = signToken(liveUserA, ROLES.USER, [
        PERMISSIONS.NOTIFICATION_READ,
      ]);
      const userBToken = signToken(liveUserB, ROLES.USER, [
        PERMISSIONS.NOTIFICATION_READ,
      ]);

      const bcRes = await requestJson(
        "POST",
        "/api/v1/notifications/broadcast",
        adminToken,
        {
          title: broadcastTitle,
          content: "Thông báo kiểm thử broadcast Issue #2",
          severity: NOTIFICATION_SEVERITY.NORMAL,
        },
      );
      assert.strictEqual(bcRes.status, 201);

      const sysCount = await notificationPrisma.notification.count({
        where: { userId: SYSTEM_BROADCAST_USER_ID, title: broadcastTitle },
      });
      assert.strictEqual(sysCount, 0);

      const listA = await requestJson(
        "GET",
        `/api/v1/notifications?search=${encodeURIComponent(broadcastTitle)}`,
        userAToken,
      );
      assert.strictEqual(listA.status, 200);
      assert.strictEqual(listA.body.meta.total, 1);
      assert.strictEqual(listA.body.data.length, 1);
      const userANotifId = listA.body.data[0].id;

      const listB = await requestJson(
        "GET",
        `/api/v1/notifications?search=${encodeURIComponent(broadcastTitle)}`,
        userBToken,
      );
      assert.strictEqual(listB.status, 200);
      assert.strictEqual(listB.body.meta.total, 1);
      assert.strictEqual(listB.body.data.length, 1);
      const userBNotifId = listB.body.data[0].id;
      assert.notStrictEqual(userANotifId, userBNotifId);

      // User A marks as read -> User B remains unread
      const readRes = await requestJson(
        "PATCH",
        `/api/v1/notifications/${userANotifId}/read`,
        userAToken,
      );
      assert.strictEqual(readRes.status, 200);

      const listBAfterRead = await requestJson(
        "GET",
        `/api/v1/notifications?search=${encodeURIComponent(broadcastTitle)}`,
        userBToken,
      );
      assert.strictEqual(listBAfterRead.body.data[0].isRead, false);

      // User A deletes -> User B still sees their notification
      const delRes = await requestJson(
        "DELETE",
        `/api/v1/notifications/${userANotifId}`,
        userAToken,
      );
      assert.strictEqual(delRes.status, 200);

      const listAAfterDel = await requestJson(
        "GET",
        `/api/v1/notifications?search=${encodeURIComponent(broadcastTitle)}`,
        userAToken,
      );
      assert.strictEqual(listAAfterDel.body.meta.total, 0);

      const listBAfterDel = await requestJson(
        "GET",
        `/api/v1/notifications?search=${encodeURIComponent(broadcastTitle)}`,
        userBToken,
      );
      assert.strictEqual(listBAfterDel.body.meta.total, 1);
    });

    it("Multi-channel IN_APP + EMAIL records should deduplicate in inbox & unread-count while exposing deliveredChannels", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_notification_db is unavailable");
        return;
      }

      const isolatedUser = crypto.randomUUID();
      const userToken = signToken(isolatedUser, ROLES.USER, [
        PERMISSIONS.NOTIFICATION_READ,
      ]);

      const inAppRow = await notificationPrisma.notification.create({
        data: {
          userId: isolatedUser,
          incidentId: liveIncidentId,
          channel: NOTIFICATION_CHANNEL.IN_APP,
          title: "Cảnh báo đa kênh PPE",
          content: "Phát hiện vi phạm đa kênh",
          severity: NOTIFICATION_SEVERITY.HIGH,
          status: NOTIFICATION_STATUS.SENT,
          sentAt: new Date(),
        },
      });
      const emailRow = await notificationPrisma.notification.create({
        data: {
          userId: isolatedUser,
          incidentId: liveIncidentId,
          channel: NOTIFICATION_CHANNEL.EMAIL,
          title: "Cảnh báo đa kênh PPE",
          content: "Phát hiện vi phạm đa kênh",
          severity: NOTIFICATION_SEVERITY.HIGH,
          status: NOTIFICATION_STATUS.SENT,
          sentAt: new Date(),
        },
      });
      createdNotificationIds.push(inAppRow.id, emailRow.id);

      const inboxRes = await requestJson(
        "GET",
        "/api/v1/notifications",
        userToken,
      );
      assert.strictEqual(inboxRes.status, 200);
      assert.strictEqual(inboxRes.body.meta.total, 1);
      assert.strictEqual(inboxRes.body.data.length, 1);
      assert.strictEqual(inboxRes.body.data[0].id, inAppRow.id);
      assert.deepStrictEqual(
        inboxRes.body.data[0].deliveredChannels.sort(),
        [NOTIFICATION_CHANNEL.EMAIL, NOTIFICATION_CHANNEL.IN_APP].sort(),
      );

      const unreadRes = await requestJson(
        "GET",
        "/api/v1/notifications/unread-count",
        userToken,
      );
      assert.strictEqual(unreadRes.status, 200);
      assert.strictEqual(unreadRes.body.data.unreadCount, 1);

      // Explicit ?channel=EMAIL still retrieves the EMAIL channel row
      const emailChannelRes = await requestJson(
        "GET",
        "/api/v1/notifications?channel=EMAIL",
        userToken,
      );
      assert.strictEqual(emailChannelRes.status, 200);
      assert.strictEqual(emailChannelRes.body.meta.total, 1);
      assert.strictEqual(emailChannelRes.body.data[0].id, emailRow.id);
    });

    it("Archive endpoints should move notifications between inbox and archived views and support archive-read", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_notification_db is unavailable");
        return;
      }

      const archUser = crypto.randomUUID();
      const token = signToken(archUser, ROLES.USER, [
        PERMISSIONS.NOTIFICATION_READ,
      ]);

      const n1 = await notificationPrisma.notification.create({
        data: {
          userId: archUser,
          channel: NOTIFICATION_CHANNEL.IN_APP,
          title: "Archive Item 1",
          content: "Unread item",
          severity: NOTIFICATION_SEVERITY.NORMAL,
          status: NOTIFICATION_STATUS.SENT,
        },
      });
      const n2 = await notificationPrisma.notification.create({
        data: {
          userId: archUser,
          channel: NOTIFICATION_CHANNEL.IN_APP,
          title: "Archive Item 2",
          content: "Read item",
          severity: NOTIFICATION_SEVERITY.NORMAL,
          status: NOTIFICATION_STATUS.READ,
          readAt: new Date(),
        },
      });
      createdNotificationIds.push(n1.id, n2.id);

      // 1. Archive unread n1 -> removed from inbox and unreadCount becomes 0
      const archRes = await requestJson(
        "PATCH",
        `/api/v1/notifications/${n1.id}/archive`,
        token,
      );
      assert.strictEqual(archRes.status, 200);

      const unreadAfterArch = await requestJson(
        "GET",
        "/api/v1/notifications/unread-count",
        token,
      );
      assert.strictEqual(unreadAfterArch.body.data.unreadCount, 0);

      const archivedList = await requestJson(
        "GET",
        "/api/v1/notifications?archived=true",
        token,
      );
      assert.strictEqual(archivedList.status, 200);
      assert.strictEqual(archivedList.body.meta.total, 1);
      assert.strictEqual(archivedList.body.data[0].id, n1.id);

      // 2. Unarchive n1 -> back in inbox & unreadCount = 1
      const unarchRes = await requestJson(
        "PATCH",
        `/api/v1/notifications/${n1.id}/unarchive`,
        token,
      );
      assert.strictEqual(unarchRes.status, 200);

      const unreadAfterUnarch = await requestJson(
        "GET",
        "/api/v1/notifications/unread-count",
        token,
      );
      assert.strictEqual(unreadAfterUnarch.body.data.unreadCount, 1);

      // 3. archive-read archives only n2 (READ), leaving n1 (SENT) in inbox
      const archReadRes = await requestJson(
        "PATCH",
        "/api/v1/notifications/archive-read",
        token,
      );
      assert.strictEqual(archReadRes.status, 200);
      assert.strictEqual(archReadRes.body.data.archivedCount, 1);

      const inboxFinal = await requestJson(
        "GET",
        "/api/v1/notifications",
        token,
      );
      assert.strictEqual(inboxFinal.body.meta.total, 1);
      assert.strictEqual(inboxFinal.body.data[0].id, n1.id);
    });

    it("GET /emails should filter by fromDate/toDate and share unified permissions with POST /emails/:id/retry", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_notification_db is unavailable");
        return;
      }

      const dOld = new Date("2026-11-10T05:00:00.000Z");
      const dMid = new Date("2026-11-20T05:00:00.000Z");
      const dNew = new Date("2026-11-25T05:00:00.000Z");

      const eOld = await (notificationPrisma as any).emailNotification.create({
        data: {
          toEmail: `old-${emailTag}@smartppe.local`,
          subject: `Old ${emailTag}`,
          templateKey: "PPE_VIOLATION_ALERT",
          templateData: {},
          status: EMAIL_STATUS.SENT,
          createdAt: dOld,
        },
      });
      const eMid = await (notificationPrisma as any).emailNotification.create({
        data: {
          toEmail: `mid-${emailTag}@smartppe.local`,
          subject: `Mid ${emailTag}`,
          templateKey: "PPE_VIOLATION_ALERT",
          templateData: {},
          status: EMAIL_STATUS.FAILED,
          createdAt: dMid,
        },
      });
      const eNew = await (notificationPrisma as any).emailNotification.create({
        data: {
          toEmail: `new-${emailTag}@smartppe.local`,
          subject: `New ${emailTag}`,
          templateKey: "PPE_VIOLATION_ALERT",
          templateData: {},
          status: EMAIL_STATUS.SENT,
          createdAt: dNew,
        },
      });
      createdEmailIds.push(eOld.id, eMid.id, eNew.id);

      const templateMgrToken = signToken(liveUserA, ROLES.SAFETY_MANAGER, [
        PERMISSIONS.NOTIFICATION_TEMPLATE_MANAGE,
      ]);
      const updaterToken = signToken(liveUserA, ROLES.SAFETY_OFFICER, [
        PERMISSIONS.NOTIFICATION_UPDATE,
      ]);
      const readerOnlyToken = signToken(liveUserA, ROLES.USER, [
        PERMISSIONS.NOTIFICATION_READ,
      ]);

      // 1. Date filtering with toEmail tag
      const filteredRes = await requestJson(
        "GET",
        `/api/v1/notifications/emails?toEmail=${emailTag}&fromDate=2026-11-15&toDate=2026-11-22`,
        templateMgrToken,
      );
      assert.strictEqual(filteredRes.status, 200);
      assert.strictEqual(filteredRes.body.meta.total, 1);
      assert.strictEqual(filteredRes.body.data[0].id, eMid.id);

      // 2. NOTIFICATION_UPDATE token can access GET /emails AND POST /emails/:id/retry
      const updaterListRes = await requestJson(
        "GET",
        `/api/v1/notifications/emails?toEmail=${emailTag}`,
        updaterToken,
      );
      assert.strictEqual(updaterListRes.status, 200);
      assert.strictEqual(updaterListRes.body.meta.total, 3);

      const retryRes = await requestJson(
        "POST",
        `/api/v1/notifications/emails/${eMid.id}/retry`,
        updaterToken,
      );
      assert.strictEqual(retryRes.status, 200);

      // 3. NOTIFICATION_READ-only token receives 403 on both
      const readerGetRes = await requestJson(
        "GET",
        `/api/v1/notifications/emails?toEmail=${emailTag}`,
        readerOnlyToken,
      );
      assert.strictEqual(readerGetRes.status, 403);

      const readerRetryRes = await requestJson(
        "POST",
        `/api/v1/notifications/emails/${eMid.id}/retry`,
        readerOnlyToken,
      );
      assert.strictEqual(readerRetryRes.status, 403);

      // 4. Invalid date range returns 422
      const badRangeRes = await requestJson(
        "GET",
        "/api/v1/notifications/emails?fromDate=2026-11-26&toDate=2026-11-01",
        templateMgrToken,
      );
      assert.strictEqual(badRangeRes.status, 422);
    });
  });
});
