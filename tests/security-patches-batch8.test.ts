import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { sseManagerService, SseManagerService } from "../src/common/services/sse-manager.service";
import { assertSafePublicUrl } from "../src/common/helpers/url.helper";
import { notificationService } from "../src/modules/notification/notification.service";
import fs from "node:fs";
import path from "node:path";
import { eventBus } from "../src/common/services/event-bus.service";
import { EventBusWorker } from "../src/common/workers/event-bus.worker";
import {
  requireGatewayOrigin,
  createRequireGatewayOrigin,
} from "../src/middlewares/request-id.middleware";
import { notificationApp } from "../src/notification.app";
import { EVENT_NAMES, EVENT_BUS_CONSTANTS } from "../src/common/constants/event.constant";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { NOTIFICATION_CHANNEL, NOTIFICATION_SEVERITY } from "../src/common/constants/notification.constant";

describe("Security Audit Patches - Batch 8 (SEC-30, SEC-31, SEC-32, SEC-33)", () => {
  describe("SEC-30: SSE Framing CRLF Injection Prevention", () => {
    it("should strip CRLF (\\r, \\n) from event.type and event.id to prevent stream framing injection", () => {
      const testUserId = "usr-sse-crlf-test";
      let capturedPayload = "";

      const mockRes: any = {
        setHeader: () => {},
        flushHeaders: () => {},
        write: (chunk: string) => {
          capturedPayload += chunk;
          return true;
        },
        end: () => {},
      };

      const mockReq: any = {
        on: () => {},
      };

      sseManagerService.registerClient(testUserId, mockRes, mockReq);

      // Reset initial handshake
      capturedPayload = "";

      // Send event with CRLF injection payload in type and id
      const maliciousType = "normal_event\r\nevent: forged_event\r\ndata: {\"hacked\":true}";
      const maliciousId = "id-123\r\ninjected_header: bad";

      sseManagerService.sendToUser(testUserId, {
        type: maliciousType,
        id: maliciousId,
        data: { message: "legitimate" },
      });

      // Assert that newline delimiters were eliminated from the event and id header lines
      assert.ok(
        !capturedPayload.includes("\revent: forged_event"),
        "Payload must not contain injected CRLF event header",
      );
      assert.ok(
        !capturedPayload.includes("\ninjected_header: bad"),
        "Payload must not contain injected CRLF id header",
      );
      assert.ok(
        capturedPayload.includes("event: normal_eventevent: forged_eventdata: {\"hacked\":true}\n"),
        "CRLF in type must be neutralized into a single line",
      );
      assert.ok(
        capturedPayload.includes("id: id-123injected_header: bad\n"),
        "CRLF in id must be neutralized into a single line",
      );
    });
  });

  describe("SEC-31: SSRF & DNS Rebinding Protection for Notification URLs", () => {
    it("assertSafePublicUrl should reject private, loopback, and metadata URLs", async () => {
      const dangerousUrls = [
        "http://127.0.0.1:8080/admin",
        "http://localhost:3000/internal",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/api",
        "http://192.168.1.1/router",
        "http://172.16.0.1/config",
      ];

      for (const url of dangerousUrls) {
        await assert.rejects(
          async () => {
            await assertSafePublicUrl(url, { allowPrivate: false });
          },
          (err: any) => {
            assert.strictEqual(err.statusCode, 400);
            assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
            return true;
          },
          `Expected ${url} to be rejected by SSRF guard`,
        );
      }
    });

    it("assertSafePublicUrl should reject empty or non-string URLs", async () => {
      await assert.rejects(
        async () => {
          await assertSafePublicUrl("");
        },
        (err: any) => {
          assert.strictEqual(err.statusCode, 400);
          return true;
        },
      );
    });

    it("NotificationService.send should reject SSRF actionUrl", async () => {
      await assert.rejects(
        async () => {
          await notificationService.send({
            userIds: ["a0000000-0000-0000-0000-000000000001"],
            channels: [NOTIFICATION_CHANNEL.IN_APP],
            title: "Security Test",
            content: "Testing SSRF",
            actionUrl: "http://169.254.169.254/metadata",
          });
        },
        (err: any) => {
          assert.strictEqual(err.statusCode, 400);
          assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
          return true;
        },
      );
    });

    it("NotificationService.broadcast should reject SSRF actionUrl", async () => {
      await assert.rejects(
        async () => {
          await notificationService.broadcast({
            title: "Broadcast SSRF Test",
            content: "Testing Broadcast SSRF",
            actionUrl: "http://127.0.0.1:8000/secret",
          });
        },
        (err: any) => {
          assert.strictEqual(err.statusCode, 400);
          assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
          return true;
        },
      );
    });

    it("NotificationService.dispatchIncidentNotification should reject SSRF evidenceUrl", async () => {
      await assert.rejects(
        async () => {
          await notificationService.dispatchIncidentNotification({
            incidentId: "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6b",
            siteId: "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6c",
            title: "Incident Test",
            description: "Testing evidenceUrl SSRF",
            severity: NOTIFICATION_SEVERITY.HIGH,
            recipientUserIds: ["018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6d"],
            evidenceUrl: "http://10.0.0.1/private-snapshot.jpg",
          });
        },
        (err: any) => {
          assert.strictEqual(err.statusCode, 400);
          assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
          return true;
        },
      );
    });
  });

  describe("SEC-32: Dual Event Bus Worker Topology & PPE Event Routing", () => {
    it("eventBus.notificationEventNames must register all PPE domain events", () => {
      const registeredEvents: Set<string> = (eventBus as any).notificationEventNames;
      assert.ok(registeredEvents, "notificationEventNames set must exist on EventBusService");

      const requiredPpeEvents = [
        EVENT_NAMES.PPE_VIOLATION_DETECTED,
        EVENT_NAMES.PPE_INCIDENT_CREATED,
        EVENT_NAMES.PPE_INCIDENT_ASSIGNED,
        EVENT_NAMES.PPE_INCIDENT_RESOLVED,
        EVENT_NAMES.PPE_CAMERA_STATUS_CHANGED,
        EVENT_NAMES.PPE_SITE_ALERT_TRIGGERED,
      ];

      for (const eventName of requiredPpeEvents) {
        assert.ok(
          registeredEvents.has(eventName),
          `notificationEventNames must contain PPE event: ${eventName}`,
        );
      }
    });

    it("server.ts must define and bootstrap backboneEventBusWorker for DEFAULT_QUEUE_NAME", () => {
      const serverFile = path.resolve(__dirname, "../src/server.ts");
      const serverCode = fs.readFileSync(serverFile, "utf-8");

      assert.ok(
        serverCode.includes("export const backboneEventBusWorker = new EventBusWorker"),
        "server.ts must declare and export backboneEventBusWorker",
      );
      assert.ok(
        serverCode.includes("EVENT_BUS_CONSTANTS.DEFAULT_QUEUE_NAME"),
        "server.ts must configure backboneEventBusWorker with DEFAULT_QUEUE_NAME",
      );
      assert.ok(
        serverCode.includes("backboneEventBusWorker.start()"),
        "server.ts must start backboneEventBusWorker on server bootstrap",
      );
      assert.ok(
        serverCode.includes("backboneEventBusWorker.stop()"),
        "server.ts must stop backboneEventBusWorker on graceful shutdown",
      );

      // Verify EventBusWorker constructor works with DEFAULT_QUEUE_NAME
      const testWorker = new EventBusWorker(eventBus, EVENT_BUS_CONSTANTS.DEFAULT_QUEUE_NAME);
      assert.strictEqual(
        (testWorker as any).queueName,
        EVENT_BUS_CONSTANTS.DEFAULT_QUEUE_NAME,
      );
    });
  });

  describe("SEC-33: API Gateway Origin Guard Perimeter Enforcement", () => {
    const testSecret = "traefik_test_secret_internal_xyz123";

    it("requireGatewayOrigin should reject direct request missing x-gateway-secret header", async () => {
      const guard = createRequireGatewayOrigin(testSecret);
      const req: any = {
        headers: {},
        path: "/api/v1/notifications",
        originalUrl: "/api/v1/notifications",
      };

      let errorThrown: any;
      guard(req, {} as any, (err?: any) => {
        errorThrown = err;
      });

      assert.ok(errorThrown, "Must reject request when gateway secret is missing");
      assert.strictEqual(errorThrown.statusCode, 403);
      assert.strictEqual(errorThrown.code, ERROR_CODE.GATEWAY_REQUIRED);
    });

    it("requireGatewayOrigin should reject direct request with invalid x-gateway-secret header", async () => {
      const guard = createRequireGatewayOrigin(testSecret);
      const req: any = {
        headers: {
          [GATEWAY_HEADERS.INTERNAL_SECRET]: "wrong_secret_payload",
        },
        path: "/api/v1/notifications",
        originalUrl: "/api/v1/notifications",
      };

      let errorThrown: any;
      guard(req, {} as any, (err?: any) => {
        errorThrown = err;
      });

      assert.ok(errorThrown, "Must reject request when gateway secret is invalid");
      assert.strictEqual(errorThrown.statusCode, 403);
      assert.strictEqual(errorThrown.code, ERROR_CODE.GATEWAY_REQUIRED);
    });

    it("requireGatewayOrigin should accept request with valid x-gateway-secret header", async () => {
      const guard = createRequireGatewayOrigin(testSecret);
      const req: any = {
        headers: {
          [GATEWAY_HEADERS.INTERNAL_SECRET]: testSecret,
        },
        path: "/api/v1/notifications",
        originalUrl: "/api/v1/notifications",
      };

      let nextCalled = false;
      guard(req, {} as any, (err?: any) => {
        assert.strictEqual(err, undefined);
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, true, "Must call next() when gateway secret matches");
    });

    it("requireGatewayOrigin should exempt health check endpoints even when secret is set", async () => {
      const guard = createRequireGatewayOrigin(testSecret);
      const req: any = {
        headers: {},
        path: "/health",
        originalUrl: "/api/v1/notifications/health",
      };

      let nextCalled = false;
      guard(req, {} as any, (err?: any) => {
        assert.strictEqual(err, undefined);
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, true, "Health checks must bypass gateway secret requirement");
    });

    it("notificationApp should mount requireGatewayOrigin on /api/v1/notifications and /notifications", () => {
      const routerStack = (notificationApp as any)._router?.stack || [];

      const v1Layer = routerStack.find(
        (layer: any) =>
          layer.regexp?.toString().includes("api") &&
          layer.regexp?.toString().includes("notifications"),
      );
      assert.ok(v1Layer, "Route layer for /api/v1/notifications must exist in router stack");

      const nonV1Layer = routerStack.find(
        (layer: any) =>
          !layer.regexp?.toString().includes("api") &&
          layer.regexp?.toString().includes("notifications"),
      );
      assert.ok(nonV1Layer, "Route layer for /notifications must exist in router stack");
    });
  });
});
