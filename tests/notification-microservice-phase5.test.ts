/**
 * Phase 5: Notification Microservice (First Satellite Service) — Test Suite
 *
 * Bao phủ:
 *   1. Event Contract Matrix & Centralized Constants (Phase 5 additions)
 *   2. NotificationSubscriber handling: verification_requested & deactivation_requested
 *   3. Decoupled AuthService: Event publishing without synchronous mail blocking
 *   4. Sensitive Token Protection in Outbox (deactivationToken encryption at rest)
 *   5. Notification Microservice Express App (notificationApp health check & route mounting)
 *   6. Infrastructure & Traefik Routing Configuration (docker-compose & network isolation)
 *   7. Graceful Degradation & Zero Event Loss
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { uuidv7 } from "uuidv7";
import {
  EVENT_NAMES,
  EVENT_BUS_CONSTANTS,
} from "../src/common/constants/event.constant";
import {
  EventBusService,
  eventBus,
} from "../src/common/services/event-bus.service";
import { OutboxRepository } from "../src/common/repositories/outbox.repository";
import { NotificationSubscriber } from "../src/common/subscribers/notification.subscriber";
import {
  VerificationRequestedPayload,
  DeactivationRequestedPayload,
} from "../src/common/types/event.type";
import { envConfig } from "../src/config/env.config";
import notificationApp from "../src/notification.app";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

class InMemoryOutboxRepository {
  private events = new Map<string, any>();

  async create(data: {
    eventType: string;
    payload: unknown;
    aggregateId?: string | null;
  }) {
    const id = uuidv7();
    const event = {
      id,
      eventType: data.eventType,
      payload: data.payload,
      aggregateId: data.aggregateId || null,
      status: "PENDING",
      attempts: 0,
      lastError: null,
      publishedAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.events.set(id, event);
    return event;
  }

  async findById(id: string) {
    return this.events.get(id) || null;
  }

  async claimPendingEvents(batchSize: number) {
    const pending: any[] = [];
    for (const event of this.events.values()) {
      if (event.status === "PENDING") {
        event.status = "PROCESSING";
        event.updatedAt = new Date();
        pending.push(event);
        if (pending.length >= batchSize) break;
      }
    }
    return pending;
  }

  async markPublished(id: string) {
    const event = this.events.get(id);
    if (event) {
      event.status = "PUBLISHED";
      event.publishedAt = new Date();
      event.updatedAt = new Date();
    }
  }

  async markFailed(id: string, error: string, maxAttempts: number = 5) {
    const event = this.events.get(id);
    if (event) {
      event.attempts += 1;
      event.lastError = error;
      event.updatedAt = new Date();
      if (event.attempts >= maxAttempts) {
        event.status = "FAILED";
      } else {
        event.status = "PENDING";
      }
    }
  }

  async deletePublishedOlderThan(_cutoffDate: Date) {
    let count = 0;
    for (const [id, event] of this.events.entries()) {
      if (event.status === "PUBLISHED") {
        this.events.delete(id);
        count++;
      }
    }
    return count;
  }
}

describe("Phase 5: Notification Microservice Test Suite", () => {
  let customBus: EventBusService;
  let customOutboxRepo: InMemoryOutboxRepository;

  beforeEach(() => {
    customOutboxRepo = new InMemoryOutboxRepository();
    customBus = new EventBusService(customOutboxRepo as any);
  });

  afterEach(async () => {
    await customBus.close();
    eventBus.clearDlq();
    eventBus.clearProcessedCache();
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 1. Event Contract Matrix & Constants for Phase 5
  // ─────────────────────────────────────────────────────────────────────────────
  describe("1. Event Contract Matrix for Phase 5", () => {
    it("1.1 EVENT_NAMES phải chứa đầy đủ các event mới của Phase 5", () => {
      assert.strictEqual(
        EVENT_NAMES.AUTH_VERIFICATION_REQUESTED,
        "auth.verification_requested",
      );
      assert.strictEqual(
        EVENT_NAMES.AUTH_DEACTIVATION_REQUESTED,
        "auth.deactivation_requested",
      );
    });

    it("1.2 VerificationRequestedPayload contract phải đáp ứng đầy đủ thuộc tính", () => {
      const payload: VerificationRequestedPayload = {
        userId: "usr-verify-123",
        email: "verify@example.com",
        fullName: "Verify User",
        verifyToken: "tok-verify-456",
      };

      assert.strictEqual(payload.userId, "usr-verify-123");
      assert.strictEqual(payload.email, "verify@example.com");
      assert.strictEqual(payload.fullName, "Verify User");
      assert.strictEqual(payload.verifyToken, "tok-verify-456");
    });

    it("1.3 DeactivationRequestedPayload contract phải đáp ứng đầy đủ thuộc tính", () => {
      const payload: DeactivationRequestedPayload = {
        userId: "usr-deact-789",
        email: "deact@example.com",
        fullName: "Deact User",
        deactivationToken: "tok-deact-999",
      };

      assert.strictEqual(payload.userId, "usr-deact-789");
      assert.strictEqual(payload.email, "deact@example.com");
      assert.strictEqual(payload.fullName, "Deact User");
      assert.strictEqual(payload.deactivationToken, "tok-deact-999");
    });

    it("1.4 EVENT_BUS_CONSTANTS phải định nghĩa NOTIFICATION_QUEUE_NAME riêng biệt", () => {
      assert.strictEqual(
        EVENT_BUS_CONSTANTS.NOTIFICATION_QUEUE_NAME,
        "events-notification-queue",
      );
      assert.strictEqual(
        EVENT_BUS_CONSTANTS.DEFAULT_QUEUE_NAME,
        "events-backbone-queue",
      );
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 2. NotificationSubscriber Event Handling
  // ─────────────────────────────────────────────────────────────────────────────
  describe("2. NotificationSubscriber Event Handling", () => {
    it("2.1 Phải dispatch email xác thực khi nhận sự kiện auth.verification_requested", async () => {
      let dispatchedEmail = "";
      let dispatchedToken = "";
      let dispatchedName: string | undefined = "";

      const mockMailService: any = {
        sendVerificationEmail: async (
          email: string,
          token: string,
          name?: string,
        ) => {
          dispatchedEmail = email;
          dispatchedToken = token;
          dispatchedName = name;
        },
      };

      const subscriber = new NotificationSubscriber(mockMailService, customBus);
      subscriber.register();

      await customBus.dispatchDirectly({
        id: uuidv7(),
        name: EVENT_NAMES.AUTH_VERIFICATION_REQUESTED,
        payload: {
          userId: "usr-resend-1",
          email: "resend@example.com",
          fullName: "Resend User",
          verifyToken: "token-resend-xyz",
        },
        timestamp: Date.now(),
        source: "auth-service",
      });

      assert.strictEqual(dispatchedEmail, "resend@example.com");
      assert.strictEqual(dispatchedToken, "token-resend-xyz");
      assert.strictEqual(dispatchedName, "Resend User");
    });

    it("2.2 Phải dispatch email vô hiệu hóa khi nhận sự kiện auth.deactivation_requested", async () => {
      let dispatchedEmail = "";
      let dispatchedToken = "";
      let dispatchedName: string | undefined = "";

      const mockMailService: any = {
        sendAccountDeactivationEmail: async (
          email: string,
          token: string,
          name?: string,
        ) => {
          dispatchedEmail = email;
          dispatchedToken = token;
          dispatchedName = name;
        },
      };

      const subscriber = new NotificationSubscriber(mockMailService, customBus);
      subscriber.register();

      await customBus.dispatchDirectly({
        id: uuidv7(),
        name: EVENT_NAMES.AUTH_DEACTIVATION_REQUESTED,
        payload: {
          userId: "usr-deact-1",
          email: "deactivate@example.com",
          fullName: "Deactivating User",
          deactivationToken: "token-deact-abc",
        },
        timestamp: Date.now(),
        source: "auth-service",
      });

      assert.strictEqual(dispatchedEmail, "deactivate@example.com");
      assert.strictEqual(dispatchedToken, "token-deact-abc");
      assert.strictEqual(dispatchedName, "Deactivating User");
    });

    it("2.3 Subscriber ném lỗi khi mailService thất bại để kích hoạt retry/DLQ", async () => {
      const mockFailingMailService: any = {
        sendVerificationEmail: async () => {
          throw new Error("SMTP connection refused");
        },
      };

      const subscriber = new NotificationSubscriber(
        mockFailingMailService,
        customBus,
      );
      subscriber.register();

      await assert.rejects(
        customBus.dispatchDirectly({
          id: uuidv7(),
          name: EVENT_NAMES.AUTH_VERIFICATION_REQUESTED,
          payload: {
            userId: "usr-fail-1",
            email: "fail@example.com",
            verifyToken: "tok-fail",
          },
          timestamp: Date.now(),
          source: "auth-service",
        }),
        /SMTP connection refused/,
      );
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 3. Sensitive Token Protection in Outbox Payload
  // ─────────────────────────────────────────────────────────────────────────────
  describe("3. Sensitive Token Protection in Outbox (deactivationToken)", () => {
    it("3.1 deactivationToken phải được mã hóa AES-256-GCM với tiền tố enc: khi lưu outbox", () => {
      const rawToken = "super-secret-deactivation-token-777";
      const encrypted = customBus.encryptSensitivePayloadFields({
        userId: "u-deact",
        email: "test@example.com",
        deactivationToken: rawToken,
      });

      assert.notStrictEqual(encrypted.deactivationToken, rawToken);
      assert.ok(
        encrypted.deactivationToken.startsWith("enc:"),
        "deactivationToken phải có tiền tố enc:",
      );
    });

    it("3.2 deactivationToken phải được giải mã về nguyên bản khi relay từ outbox", () => {
      const rawToken = "super-secret-deactivation-token-888";
      const encrypted = customBus.encryptSensitivePayloadFields({
        userId: "u-deact-2",
        email: "test2@example.com",
        deactivationToken: rawToken,
      });

      const decrypted = customBus.decryptSensitivePayloadFields(encrypted);
      assert.strictEqual(decrypted.deactivationToken, rawToken);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 4. Notification Microservice Express App (notificationApp)
  // ─────────────────────────────────────────────────────────────────────────────
  describe("4. Notification Microservice Express App (notificationApp)", () => {
    let testServer: import("node:http").Server;
    let baseUrl: string;

    beforeEach(async () => {
      const http = await import("node:http");
      testServer = http.createServer(notificationApp);
      await new Promise<void>((resolve) => testServer.listen(0, resolve));
      const addr = testServer.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      baseUrl = `http://127.0.0.1:${port}`;
    });

    afterEach(async () => {
      await new Promise<void>((resolve) => testServer.close(() => resolve()));
    });

    it("4.1 GET /health phải trả về 200 OK với thông tin notification-service", async () => {
      const res = await fetch(`${baseUrl}/health`);
      assert.strictEqual(res.status, 200);
      const body = (await res.json()) as any;
      assert.strictEqual(body.status, "ok");
      assert.strictEqual(body.service, "notification-service");
      assert.ok(typeof body.uptime === "number");
    });

    it("4.2 GET /api/v1/notifications/health phải trả về 200 OK cho loadbalancer", async () => {
      const res = await fetch(`${baseUrl}/api/v1/notifications/health`);
      assert.strictEqual(res.status, 200);
      const body = (await res.json()) as any;
      assert.strictEqual(body.status, "ok");
      assert.strictEqual(body.service, "notification-service");
    });

    it("4.3 notificationApp phải tự động gắn header X-Request-Id vào response", async () => {
      const res = await fetch(`${baseUrl}/health`);
      const requestIdHeader = res.headers.get("x-request-id");
      assert.ok(requestIdHeader, "X-Request-Id header phải tồn tại");
      assert.ok(requestIdHeader.length > 0);
    });

    it("4.4 Yêu cầu không có token đến /api/v1/notifications phải bị chặn 401 Unauthorized", async () => {
      const res = await fetch(`${baseUrl}/api/v1/notifications`);
      assert.strictEqual(res.status, 401);
      const body = (await res.json()) as any;
      assert.strictEqual(body.success, false);
      assert.strictEqual(body.code, "UNAUTHORIZED");
    });

    it("4.5 GET /notifications/health cũng phải trả về 200 OK cho loadbalancer", async () => {
      const res = await fetch(`${baseUrl}/notifications/health`);
      assert.strictEqual(res.status, 200);
      const body = (await res.json()) as any;
      assert.strictEqual(body.status, "ok");
      assert.strictEqual(body.service, "notification-service");
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 5. Environment Config for Notification Microservice
  // ─────────────────────────────────────────────────────────────────────────────
  describe("5. Environment Config for Notification Microservice", () => {
    it("5.1 envConfig.notification phải có port, standalone, và serviceUrl", () => {
      assert.ok("port" in envConfig.notification);
      assert.strictEqual(typeof envConfig.notification.port, "number");
      assert.ok(envConfig.notification.port > 0);

      assert.ok("standalone" in envConfig.notification);
      assert.strictEqual(typeof envConfig.notification.standalone, "boolean");

      assert.ok("serviceUrl" in envConfig.notification);
      assert.strictEqual(typeof envConfig.notification.serviceUrl, "string");
    });

    it("5.2 Giá trị mặc định của NOTIFICATION_PORT phải là 8889", () => {
      if (!process.env.NOTIFICATION_PORT) {
        assert.strictEqual(envConfig.notification.port, 8889);
      }
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 6. Infrastructure & Traefik Routing Configuration
  // ─────────────────────────────────────────────────────────────────────────────
  describe("6. Infrastructure & Traefik Routing Configuration", () => {
    it("6.1 docker-compose.yml phải chứa service notification-service", () => {
      const dockerComposePath = join(process.cwd(), "docker-compose.yml");
      assert.ok(existsSync(dockerComposePath));
      const content = readFileSync(dockerComposePath, "utf-8");

      assert.ok(content.includes("notification-service:"));
      assert.ok(content.includes("dist/notification.server.js"));
      assert.ok(content.includes('NOTIFICATION_SERVICE_STANDALONE: "true"'));
    });

    it("6.2 docker-compose.yml phải cấu hình Traefik routing cho notifications với priority 100", () => {
      const dockerComposePath = join(process.cwd(), "docker-compose.yml");
      const content = readFileSync(dockerComposePath, "utf-8");

      assert.ok(
        content.includes(
          "traefik.http.routers.notifications.rule=PathPrefix(`/api/v1/notifications`)",
        ),
      );
      assert.ok(
        content.includes("traefik.http.routers.notifications.priority=100"),
      );
      assert.ok(
        content.includes(
          "traefik.http.services.notifications.loadbalancer.server.port",
        ),
      );
      assert.ok(
        content.includes(
          "traefik.http.services.notifications.loadbalancer.healthcheck.path=/health",
        ),
      );
    });

    it("6.3 docker-compose.dev.yml phải chứa override cho notification-service", () => {
      const devComposePath = join(process.cwd(), "docker-compose.dev.yml");
      assert.ok(existsSync(devComposePath));
      const content = readFileSync(devComposePath, "utf-8");

      assert.ok(content.includes("notification-service:"));
      assert.ok(content.includes("pnpm"));
      assert.ok(content.includes("dev:notification"));
    });

    it("6.4 package.json phải chứa script dev:notification và start:notification", () => {
      const pkgPath = join(process.cwd(), "package.json");
      const content = JSON.parse(readFileSync(pkgPath, "utf-8"));

      assert.ok("dev:notification" in content.scripts);
      assert.ok("start:notification" in content.scripts);
      assert.strictEqual(
        content.scripts["dev:notification"],
        "ts-node-dev --respawn --transpile-only src/notification.server.ts",
      );
      assert.strictEqual(
        content.scripts["start:notification"],
        "node dist/notification.server.js",
      );
    });

    it("6.5 .env.example phải tài liệu hóa các biến cấu hình của Notification Service", () => {
      const envExamplePath = join(process.cwd(), ".env.example");
      const content = readFileSync(envExamplePath, "utf-8");

      assert.ok(content.includes("NOTIFICATION_PORT=8889"));
      assert.ok(content.includes("NOTIFICATION_SERVICE_STANDALONE=false"));
      assert.ok(
        content.includes("NOTIFICATION_SERVICE_URL=http://localhost:8889"),
      );
    });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // 7. Graceful Degradation & Decoupled Outbox Publishing
  // ─────────────────────────────────────────────────────────────────────────────
  describe("7. Graceful Degradation & Decoupled Outbox Publishing", () => {
    it("7.1 Khi lưu outbox event auth.verification_requested, record phải được tạo với trạng thái PENDING", async () => {
      const outbox = await customOutboxRepo.create({
        eventType: EVENT_NAMES.AUTH_VERIFICATION_REQUESTED,
        payload: {
          userId: "usr-decouple-1",
          email: "decouple@example.com",
          fullName: "Decouple User",
          verifyToken: "tok-dec-123",
        },
        aggregateId: "usr-decouple-1",
      });

      assert.ok(outbox.id);
      assert.strictEqual(outbox.status, "PENDING");
      assert.strictEqual(
        outbox.eventType,
        EVENT_NAMES.AUTH_VERIFICATION_REQUESTED,
      );

      const found = await customOutboxRepo.findById(outbox.id);
      assert.ok(found);
      assert.strictEqual(found.status, "PENDING");
    });

    it("7.2 Outbox Relay chuyển giao thành công sự kiện tới subscriber của Notification Service", async () => {
      let receivedEmail = "";
      let receivedToken = "";

      const mockMailService: any = {
        sendVerificationEmail: async (email: string, token: string) => {
          receivedEmail = email;
          receivedToken = token;
        },
      };

      const subscriber = new NotificationSubscriber(mockMailService, customBus);
      subscriber.register();

      // Tạo outbox record
      const outbox = await customOutboxRepo.create({
        eventType: EVENT_NAMES.AUTH_VERIFICATION_REQUESTED,
        payload: {
          userId: "usr-relay-1",
          email: "relay@example.com",
          verifyToken: "tok-relay-456",
        },
        aggregateId: "usr-relay-1",
      });

      // Relay outbox
      const relayed = await customBus.relayPendingOutboxEvents(10);
      assert.ok(relayed >= 1);

      // Verify DB record status is PUBLISHED
      const updated = await customOutboxRepo.findById(outbox.id);
      assert.strictEqual(updated?.status, "PUBLISHED");
      assert.strictEqual(receivedEmail, "relay@example.com");
      assert.strictEqual(receivedToken, "tok-relay-456");
    });
  });
});
