import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import jwt from "jsonwebtoken";
import notificationApp from "../src/notification.app";
import { notificationPrisma } from "../src/database/notification.client";
import { jwtConfig } from "../src/config/jwt.config";
import { envConfig } from "../src/config/env.config";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { ROLES } from "../src/common/constants/role.constant";
import {
  NOTIFICATION_CHANNEL,
  NOTIFICATION_SEVERITY,
  SUPPORTED_PREFERENCE_CHANNELS,
} from "../src/common/constants/notification.constant";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { AppError } from "../src/common/errors/app-error";
import { updateNotificationPreferenceSchema } from "../src/modules/notification/notification.validation";
import { NotificationService } from "../src/modules/notification/notification.service";
import { NotificationRepository } from "../src/modules/notification/notification.repository";

describe("Issue #3: Restrict Notification Preferences to IN_APP & EMAIL", () => {
  describe("1. Zod Validation Schema (updateNotificationPreferenceSchema)", () => {
    it("accepts IN_APP and EMAIL channels", () => {
      assert.deepStrictEqual(SUPPORTED_PREFERENCE_CHANNELS, [
        NOTIFICATION_CHANNEL.IN_APP,
        NOTIFICATION_CHANNEL.EMAIL,
      ]);

      const inAppRes = updateNotificationPreferenceSchema.safeParse({
        channel: NOTIFICATION_CHANNEL.IN_APP,
        enabled: true,
        severityThreshold: NOTIFICATION_SEVERITY.LOW,
      });
      assert.strictEqual(inAppRes.success, true);

      const emailRes = updateNotificationPreferenceSchema.safeParse({
        channel: NOTIFICATION_CHANNEL.EMAIL,
        enabled: false,
        severityThreshold: NOTIFICATION_SEVERITY.HIGH,
      });
      assert.strictEqual(emailRes.success, true);
    });

    it("rejects WEBHOOK, ZALO_ZNS, and WEB channels with validation error", () => {
      for (const unsupported of [
        NOTIFICATION_CHANNEL.WEBHOOK,
        NOTIFICATION_CHANNEL.ZALO_ZNS,
        NOTIFICATION_CHANNEL.WEB,
      ]) {
        const res = updateNotificationPreferenceSchema.safeParse({
          channel: unsupported,
          enabled: true,
          severityThreshold: NOTIFICATION_SEVERITY.LOW,
        });
        assert.strictEqual(
          res.success,
          false,
          `Channel ${unsupported} must be rejected by updateNotificationPreferenceSchema`,
        );
        if (!res.success) {
          assert.strictEqual(res.error.issues[0].path[0], "channel");
        }
      }
    });
  });

  describe("2. NotificationService Defense-in-Depth & Filtering", () => {
    it("getUserPreferences filters out legacy WEBHOOK/ZALO_ZNS/WEB rows and merges defaults without DB mutation", async () => {
      let upsertCalled = false;
      const userId = "019447e1-9999-7000-8000-000000000111";
      const mockRepo = {
        findUserPreferences: async () => [
          {
            id: "pref-in-app",
            userId,
            channel: NOTIFICATION_CHANNEL.IN_APP,
            enabled: false,
            severityThreshold: NOTIFICATION_SEVERITY.MEDIUM,
            createdAt: new Date("2026-11-01T00:00:00.000Z"),
            updatedAt: new Date("2026-11-01T00:00:00.000Z"),
          },
          {
            id: "pref-legacy-webhook",
            userId,
            channel: NOTIFICATION_CHANNEL.WEBHOOK,
            enabled: true,
            severityThreshold: NOTIFICATION_SEVERITY.LOW,
            createdAt: new Date("2026-10-01T00:00:00.000Z"),
            updatedAt: new Date("2026-10-01T00:00:00.000Z"),
          },
          {
            id: "pref-legacy-zalo",
            userId,
            channel: NOTIFICATION_CHANNEL.ZALO_ZNS,
            enabled: true,
            severityThreshold: NOTIFICATION_SEVERITY.HIGH,
            createdAt: new Date("2026-10-01T00:00:00.000Z"),
            updatedAt: new Date("2026-10-01T00:00:00.000Z"),
          },
          {
            id: "pref-legacy-web",
            userId,
            channel: NOTIFICATION_CHANNEL.WEB,
            enabled: true,
            severityThreshold: NOTIFICATION_SEVERITY.LOW,
            createdAt: new Date("2026-10-01T00:00:00.000Z"),
            updatedAt: new Date("2026-10-01T00:00:00.000Z"),
          },
        ],
        upsertPreference: async () => {
          upsertCalled = true;
          throw new Error("SEC-44: GET must not mutate DB");
        },
      } as unknown as NotificationRepository;

      const service = new NotificationService(mockRepo);
      const prefs = await service.getUserPreferences(userId);

      assert.strictEqual(upsertCalled, false);
      assert.strictEqual(prefs.length, 2);
      assert.deepStrictEqual(
        prefs.map((p) => p.channel).sort(),
        [NOTIFICATION_CHANNEL.EMAIL, NOTIFICATION_CHANNEL.IN_APP],
      );

      const inApp = prefs.find((p) => p.channel === NOTIFICATION_CHANNEL.IN_APP);
      assert.strictEqual(inApp?.enabled, false);
      assert.strictEqual(inApp?.severityThreshold, NOTIFICATION_SEVERITY.MEDIUM);

      const email = prefs.find((p) => p.channel === NOTIFICATION_CHANNEL.EMAIL);
      assert.strictEqual(email?.enabled, true);
      assert.strictEqual(email?.severityThreshold, NOTIFICATION_SEVERITY.HIGH);
    });

    it("updateUserPreference rejects unsupported channels with 400 VALIDATION_ERROR and allows IN_APP/EMAIL", async () => {
      let upsertCalls = 0;
      const userId = "019447e1-9999-7000-8000-000000000112";
      const mockRepo = {
        upsertPreference: async (
          uid: string,
          channel: string,
          enabled: boolean,
          severityThreshold: string,
        ) => {
          upsertCalls++;
          return {
            id: `pref-${channel}`,
            userId: uid,
            channel,
            enabled,
            severityThreshold,
            createdAt: new Date(),
            updatedAt: new Date(),
          };
        },
      } as unknown as NotificationRepository;

      const service = new NotificationService(mockRepo);

      for (const unsupported of [
        NOTIFICATION_CHANNEL.WEBHOOK,
        NOTIFICATION_CHANNEL.ZALO_ZNS,
        NOTIFICATION_CHANNEL.WEB,
      ]) {
        await assert.rejects(
          () =>
            service.updateUserPreference(userId, {
              channel: unsupported as any,
              enabled: true,
              severityThreshold: NOTIFICATION_SEVERITY.LOW,
            }),
          (err: any) =>
            err instanceof AppError &&
            err.statusCode === 400 &&
            err.code === ERROR_CODE.VALIDATION_ERROR,
        );
      }
      assert.strictEqual(upsertCalls, 0);

      const saved = await service.updateUserPreference(userId, {
        channel: NOTIFICATION_CHANNEL.EMAIL,
        enabled: false,
        severityThreshold: NOTIFICATION_SEVERITY.CRITICAL,
      });
      assert.strictEqual(upsertCalls, 1);
      assert.strictEqual(saved.channel, NOTIFICATION_CHANNEL.EMAIL);
      assert.strictEqual(saved.enabled, false);
    });

    it("send() regression: continues blocking WEBHOOK and ZALO_ZNS with 400 BAD_REQUEST (SEC-27)", async () => {
      const service = new NotificationService(
        {} as unknown as NotificationRepository,
        {} as any,
        {} as any,
        {
          isFeatureEnabled: async () => true,
        } as any,
      );

      await assert.rejects(
        () =>
          service.send({
            userIds: ["019447e1-9999-7000-8000-000000000113"],
            channels: [NOTIFICATION_CHANNEL.WEBHOOK],
            title: "Test",
            content: "Test",
          }),
        (err: any) =>
          err instanceof AppError &&
          err.statusCode === 400 &&
          err.code === ERROR_CODE.BAD_REQUEST,
      );
    });
  });

  describe("3. Live HTTP + PostgreSQL (ppe_notification_db) Integration Tests", () => {
    let dbAvailable = false;
    let server: http.Server | null = null;
    let baseUrl = "";
    let origPublicKey = "";
    let testPrivateKey = "";

    const testUserId = crypto.randomUUID();
    let userToken = "";

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

      userToken = jwt.sign(
        {
          id: testUserId,
          email: "pref-test@smartppe.local",
          role: ROLES.SAFETY_OFFICER,
          permissions: [PERMISSIONS.NOTIFICATION_READ],
          purpose: JWT_PURPOSE.ACCESS,
          mustChangePassword: false,
        },
        testPrivateKey,
        { algorithm: "RS256", expiresIn: "15m" },
      );

      // Seed an IN_APP row + legacy WEBHOOK row directly in DB
      await notificationPrisma.notificationPreference.createMany({
        data: [
          {
            userId: testUserId,
            channel: NOTIFICATION_CHANNEL.IN_APP,
            enabled: true,
            severityThreshold: NOTIFICATION_SEVERITY.MEDIUM,
          },
          {
            userId: testUserId,
            channel: NOTIFICATION_CHANNEL.WEBHOOK,
            enabled: true,
            severityThreshold: NOTIFICATION_SEVERITY.LOW,
          },
        ],
      });

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
        await notificationPrisma.notificationPreference
          .deleteMany({ where: { userId: testUserId } })
          .catch(() => {});
      }
      if (server) {
        await new Promise<void>((resolve) => {
          server!.close(() => resolve());
        });
      }
      await notificationPrisma.$disconnect().catch(() => {});
    });

    it("GET /preferences omits legacy WEBHOOK row and returns only IN_APP & EMAIL; PUT /preferences rejects unsupported channels and accepts EMAIL", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_notification_db is unavailable");
        return;
      }

      const getRes = await requestJson(
        "GET",
        "/api/v1/notifications/preferences",
        userToken,
      );
      assert.strictEqual(getRes.status, 200);
      assert.strictEqual(getRes.body.success, true);
      assert.strictEqual(getRes.body.data.length, 2);
      assert.deepStrictEqual(
        (getRes.body.data as any[]).map((p) => p.channel).sort(),
        [NOTIFICATION_CHANNEL.EMAIL, NOTIFICATION_CHANNEL.IN_APP],
      );

      for (const unsupported of [
        NOTIFICATION_CHANNEL.WEBHOOK,
        NOTIFICATION_CHANNEL.ZALO_ZNS,
        NOTIFICATION_CHANNEL.WEB,
      ]) {
        const putBadRes = await requestJson(
          "PUT",
          "/api/v1/notifications/preferences",
          userToken,
          {
            channel: unsupported,
            enabled: true,
            severityThreshold: NOTIFICATION_SEVERITY.LOW,
          },
        );
        assert.strictEqual(
          putBadRes.status,
          422,
          `PUT /preferences with ${unsupported} must fail validation`,
        );
        assert.strictEqual(putBadRes.body.code, ERROR_CODE.VALIDATION_ERROR);
      }

      const putEmailRes = await requestJson(
        "PUT",
        "/api/v1/notifications/preferences",
        userToken,
        {
          channel: NOTIFICATION_CHANNEL.EMAIL,
          enabled: false,
          severityThreshold: NOTIFICATION_SEVERITY.CRITICAL,
        },
      );
      assert.strictEqual(putEmailRes.status, 200);
      assert.strictEqual(putEmailRes.body.data.channel, NOTIFICATION_CHANNEL.EMAIL);
      assert.strictEqual(putEmailRes.body.data.enabled, false);
      assert.strictEqual(
        putEmailRes.body.data.severityThreshold,
        NOTIFICATION_SEVERITY.CRITICAL,
      );
    });
  });
});
