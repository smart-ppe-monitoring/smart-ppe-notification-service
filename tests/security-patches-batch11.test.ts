import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { Request, Response, NextFunction } from "express";
import { NotificationService } from "../src/modules/notification/notification.service";
import { NotificationRepository } from "../src/modules/notification/notification.repository";
import {
  NOTIFICATION_CHANNEL,
  NOTIFICATION_SEVERITY,
  DEFAULT_PREFERENCES,
} from "../src/common/constants/notification.constant";
import { authRateLimitMiddleware } from "../src/middlewares/rate-limit.middleware";
import { ERROR_CODE } from "../src/common/errors/error-code";

describe("Security Audit Patches - Batch 11 (SEC-42, SEC-43, SEC-44)", () => {
  // ─────────────────────────────────────────────
  // SEC-42: Process Lifecycle Unhandled Rejection & Uncaught Exception Traps
  // ─────────────────────────────────────────────
  describe("SEC-42: Process Lifecycle Exception & Rejection Traps", () => {
    it("server.ts must register listeners for unhandledRejection and uncaughtException", () => {
      const serverFile = path.resolve(__dirname, "../src/server.ts");
      const serverCode = fs.readFileSync(serverFile, "utf-8");

      assert.ok(
        serverCode.includes('process.on("unhandledRejection"'),
        "server.ts must register process.on('unhandledRejection')",
      );
      assert.ok(
        serverCode.includes('process.on("uncaughtException"'),
        "server.ts must register process.on('uncaughtException')",
      );
      assert.ok(
        serverCode.includes('handleNotificationShutdown("uncaughtException")'),
        "server.ts must invoke handleNotificationShutdown upon uncaughtException",
      );
    });

    it("handleNotificationShutdown must set exit code 1 for uncaughtException", () => {
      const serverFile = path.resolve(__dirname, "../src/server.ts");
      const serverCode = fs.readFileSync(serverFile, "utf-8");

      assert.ok(
        serverCode.includes('signal === "uncaughtException" ? 1 : 0'),
        "handleNotificationShutdown must exit with status code 1 when terminating due to uncaughtException",
      );
    });
  });

  // ─────────────────────────────────────────────
  // SEC-43: Dedicated Rate Limiter on POST /stream-ticket
  // ─────────────────────────────────────────────
  describe("SEC-43: Dedicated Rate Limiter on Realtime Stream Ticket Issuance", () => {
    it("notification.route.ts must mount authRateLimitMiddleware on /stream-ticket", () => {
      const routeFile = path.resolve(__dirname, "../src/modules/notification/notification.route.ts");
      const routeCode = fs.readFileSync(routeFile, "utf-8");

      assert.ok(
        routeCode.includes('router.post(') &&
          routeCode.includes('"/stream-ticket"') &&
          routeCode.includes("authRateLimitMiddleware"),
        "notification.route.ts must mount authRateLimitMiddleware on POST /stream-ticket",
      );
    });

    it("authRateLimitMiddleware must block requests exceeding max threshold with HTTP 429", async () => {
      const clientIp = "192.168.1.99";
      let statusCode = 200;
      let jsonPayload: any = null;
      let nextCalled = 0;

      const mockReq = {
        ip: clientIp,
        headers: {},
        user: { id: "user-rate-limit-test" },
      } as unknown as Request;

      const mockRes = {
        setHeader: () => {},
        status: (code: number) => {
          statusCode = code;
          return {
            json: (payload: any) => {
              jsonPayload = payload;
            },
          };
        },
      } as unknown as Response;

      const mockNext = () => {
        nextCalled += 1;
      };

      // Gọi authRateLimitMiddleware nhiều lần để vượt ngưỡng
      for (let i = 0; i < 40; i++) {
        authRateLimitMiddleware(mockReq, mockRes, mockNext);
      }

      assert.ok(nextCalled > 0, "Initial calls must pass through to next");
      assert.equal(statusCode, 429, "Exceeded calls must receive HTTP 429");
      assert.equal(jsonPayload.success, false);
      assert.equal(jsonPayload.code, ERROR_CODE.RATE_LIMIT_EXCEEDED);
    });
  });

  // ─────────────────────────────────────────────
  // SEC-44: HTTP Safe Method (GET /preferences) Database Mutation Prevention
  // ─────────────────────────────────────────────
  describe("SEC-44: Safe HTTP Method Conformance on GET /preferences", () => {
    it("getUserPreferences must NOT execute upsertPreference or mutate database when user has no preferences", async () => {
      let upsertCallCount = 0;

      const mockRepo = {
        findUserPreferences: async (_userId: string) => [],
        upsertPreference: async () => {
          upsertCallCount += 1;
          throw new Error("MUTATION_PROHIBITED: upsertPreference should not be called during GET /preferences");
        },
      } as unknown as NotificationRepository;

      const service = new NotificationService(mockRepo, undefined, undefined, undefined);

      const preferences = await service.getUserPreferences("user-new-officer-1");

      assert.equal(upsertCallCount, 0, "No database writes (upsert) must occur during safe GET read");
      assert.equal(preferences.length, DEFAULT_PREFERENCES.length);

      const inAppPref = preferences.find((p) => p.channel === NOTIFICATION_CHANNEL.IN_APP);
      assert.ok(inAppPref, "In-app default preference must be synthesized in-memory");
      assert.equal(inAppPref.enabled, true);
      assert.equal(inAppPref.severityThreshold, NOTIFICATION_SEVERITY.LOW);

      const emailPref = preferences.find((p) => p.channel === NOTIFICATION_CHANNEL.EMAIL);
      assert.ok(emailPref, "Email default preference must be synthesized in-memory");
      assert.equal(emailPref.enabled, true);
      assert.equal(emailPref.severityThreshold, NOTIFICATION_SEVERITY.HIGH);
    });

    it("getUserPreferences must merge existing saved preference with in-memory defaults without database write", async () => {
      let upsertCallCount = 0;

      const existingEmailPreference = {
        id: "pref-custom-email-1",
        userId: "user-existing-1",
        channel: NOTIFICATION_CHANNEL.EMAIL,
        enabled: false,
        severityThreshold: NOTIFICATION_SEVERITY.CRITICAL,
        createdAt: new Date("2026-01-01"),
        updatedAt: new Date("2026-01-02"),
      };

      const mockRepo = {
        findUserPreferences: async (_userId: string) => [existingEmailPreference],
        upsertPreference: async () => {
          upsertCallCount += 1;
          throw new Error("MUTATION_PROHIBITED: upsertPreference should not be called during GET /preferences");
        },
      } as unknown as NotificationRepository;

      const service = new NotificationService(mockRepo, undefined, undefined, undefined);

      const preferences = await service.getUserPreferences("user-existing-1");

      assert.equal(upsertCallCount, 0, "No database writes must occur when merging partial preferences");
      assert.equal(preferences.length, 2);

      const emailPref = preferences.find((p) => p.channel === NOTIFICATION_CHANNEL.EMAIL);
      assert.ok(emailPref);
      assert.equal(emailPref.id, "pref-custom-email-1");
      assert.equal(emailPref.enabled, false);
      assert.equal(emailPref.severityThreshold, NOTIFICATION_SEVERITY.CRITICAL);

      const inAppPref = preferences.find((p) => p.channel === NOTIFICATION_CHANNEL.IN_APP);
      assert.ok(inAppPref);
      assert.equal(inAppPref.enabled, true);
      assert.equal(inAppPref.severityThreshold, NOTIFICATION_SEVERITY.LOW);
    });

    it("updateUserPreference must continue to call upsertPreference for genuine mutation requests", async () => {
      let upsertCalled = false;
      let savedChannel = "";
      let savedEnabled = false;

      const mockRepo = {
        upsertPreference: async (
          _userId: string,
          channel: string,
          enabled: boolean,
          severityThreshold: string,
        ) => {
          upsertCalled = true;
          savedChannel = channel;
          savedEnabled = enabled;
          return {
            id: "pref-updated-1",
            userId: "user-1",
            channel,
            enabled,
            severityThreshold,
            createdAt: new Date(),
            updatedAt: new Date(),
          };
        },
      } as unknown as NotificationRepository;

      const service = new NotificationService(mockRepo, undefined, undefined, undefined);

      const result = await service.updateUserPreference("user-1", {
        channel: NOTIFICATION_CHANNEL.EMAIL,
        enabled: true,
        severityThreshold: NOTIFICATION_SEVERITY.MEDIUM,
      });

      assert.equal(upsertCalled, true, "updateUserPreference must call upsertPreference");
      assert.equal(savedChannel, NOTIFICATION_CHANNEL.EMAIL);
      assert.equal(savedEnabled, true);
      assert.equal(result.id, "pref-updated-1");
    });
  });
});
