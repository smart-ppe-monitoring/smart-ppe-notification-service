import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import jwt from "jsonwebtoken";
import { jwtConfig } from "../src/config/jwt.config";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import { createRequireInternalServiceToken } from "../src/middlewares/internal-auth.middleware";
import {
  isSafeInternalEvidencePath,
  isTrustedMinioEvidenceUrl,
  isSafeEvidenceUrl,
  assertSafeEvidenceUrl,
} from "../src/common/helpers/url.helper";
import { dispatchIncidentNotificationSchema } from "../src/modules/notification/notification.validation";
import {
  NotificationService,
  IncidentClient,
  IdentityClient,
  isAutomatedTestRuntime,
} from "../src/modules/notification/notification.service";
import { NotificationRepository } from "../src/modules/notification/notification.repository";
import { MailService } from "../src/common/services/mail.service";
import { SseManagerService } from "../src/common/services/sse-manager.service";
import { EmailTemplateService } from "../src/common/services/email-template.service";
import { SystemConfigCacheService } from "../src/common/services/system-config-cache.service";
import { EmailWorker } from "../src/common/workers/email-worker";
import { NotificationSubscriber } from "../src/common/subscribers/notification.subscriber";
import { EventBusService } from "../src/common/services/event-bus.service";
import { EVENT_NAMES } from "../src/common/constants/event.constant";
import {
  FEATURE_FLAGS,
  SYSTEM_CONFIG_PUBSUB_CHANNEL,
} from "../src/common/constants/system-config.constant";
import notificationRoute from "../src/modules/notification/notification.route";
import { authMiddleware } from "../src/middlewares/auth.middleware";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";
import { NOTIFICATION_CHANNEL, NOTIFICATION_SEVERITY } from "../src/common/constants/notification.constant";
import { ROLES } from "../src/common/constants/role.constant";

describe("Internal Incident Notification Trigger & Evidence SSRF Guard", () => {
  describe("requireInternalServiceToken middleware", () => {
    it("should fail closed (503/401/403) and pass on matching token", () => {
      let err503: any;
      createRequireInternalServiceToken("")({ headers: {} } as any, {} as any, (e?: any) => (err503 = e));
      assert.strictEqual(err503?.statusCode, 503);

      const mw = createRequireInternalServiceToken("internal-m2m-secret");
      let err401: any;
      mw({ headers: {} } as any, {} as any, (e?: any) => (err401 = e));
      assert.strictEqual(err401?.statusCode, 401);

      let err403: any;
      mw({ headers: { [GATEWAY_HEADERS.INTERNAL_SERVICE_TOKEN]: "bad" } } as any, {} as any, (e?: any) => (err403 = e));
      assert.strictEqual(err403?.statusCode, 403);

      let errOk: any = "unset";
      mw({ headers: { [GATEWAY_HEADERS.INTERNAL_SERVICE_TOKEN]: "internal-m2m-secret" } } as any, {} as any, (e?: any) => (errOk = e));
      assert.strictEqual(errOk, undefined);
    });
  });

  describe("Route ordering for POST /internal/trigger-incident", () => {
    it("must mount POST /internal/trigger-incident BEFORE router.use(authMiddleware)", () => {
      const stack = notificationRoute.stack || [];
      const internalIdx = stack.findIndex((layer: any) => layer.route?.path === "/internal/trigger-incident" && layer.route?.methods?.post);
      const commentIdx = stack.findIndex((layer: any) => layer.route?.path === "/internal/trigger-incident-comment" && layer.route?.methods?.post);
      const authIdx = stack.findIndex((layer: any) => !layer.route && layer.handle === authMiddleware);
      assert.ok(internalIdx !== -1, "POST /internal/trigger-incident must exist");
      assert.ok(commentIdx !== -1, "POST /internal/trigger-incident-comment must exist");
      assert.ok(authIdx !== -1, "authMiddleware must exist on notification router");
      assert.ok(internalIdx < authIdx, "internal M2M route must precede user authMiddleware");
      assert.ok(commentIdx < authIdx, "internal comment M2M route must precede user authMiddleware");
    });
  });

  describe("Safe Evidence URL & SSRF Rules", () => {
    it("should allow relative internal evidence download path and block traversal/protocol-relative tricks", () => {
      assert.strictEqual(
        isSafeInternalEvidencePath("/api/v1/incidents/evidences/018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6b/download"),
        true,
      );
      assert.strictEqual(
        isSafeInternalEvidencePath("/api/v1/evidences/018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6b/download"),
        true,
      );
      assert.strictEqual(isSafeInternalEvidencePath("//evil.com/api/v1/incidents/evidences/12345678/download"), false);
      assert.strictEqual(isSafeInternalEvidencePath("/api/v1/incidents/evidences/../../etc/passwd/download"), false);
      assert.strictEqual(isSafeInternalEvidencePath("javascript:alert(1)"), false);
    });

    it("should allow configured MinIO origin + bucket only and reject arbitrary private URLs", async () => {
      assert.strictEqual(
        isTrustedMinioEvidenceUrl("http://ppe-minio:9000/ppe-evidences/site-1/cam-1/snap.jpg", "http://ppe-minio:9000", "ppe-evidences"),
        true,
      );
      assert.strictEqual(
        isTrustedMinioEvidenceUrl("http://ppe-minio:9000/other-bucket/snap.jpg", "http://ppe-minio:9000", "ppe-evidences"),
        false,
      );
      assert.strictEqual(
        isSafeEvidenceUrl("http://10.0.0.1/private-snapshot.jpg", { minioEndpoint: "http://ppe-minio:9000", bucketName: "ppe-evidences", allowPrivate: false }),
        false,
      );
      await assertSafeEvidenceUrl("/api/v1/incidents/evidences/018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6b/download");
      await assertSafeEvidenceUrl("http://ppe-minio:9000/ppe-evidences/site-1/snap.jpg", {
        minioEndpoint: "http://ppe-minio:9000",
        bucketName: "ppe-evidences",
      });
      await assert.rejects(
        () => assertSafeEvidenceUrl("http://169.254.169.254/latest/meta-data/", { allowPrivate: false }),
        (err: any) => err.statusCode === 400 && err.code === ERROR_CODE.VALIDATION_ERROR,
      );
    });

    it("dispatchIncidentNotificationSchema should accept internal download path for evidenceUrl", () => {
      const parsed = dispatchIncidentNotificationSchema.safeParse({
        incidentId: "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6b",
        siteId: "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6c",
        cameraId: "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6d",
        cameraCode: "CAM-01",
        violationType: "NO_HELMET",
        severity: "HIGH",
        evidenceUrl: "/api/v1/incidents/evidences/018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6e/download",
        referenceEvidenceUrl: "/api/v1/incidents/evidences/018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6f/download",
      });
      assert.strictEqual(parsed.success, true);
    });
  });

  describe("NotificationService.dispatchIncidentNotification M2M Recipient Resolution & SSE", () => {
    const incidentId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6b";
    const siteId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6c";
    const cameraId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6d";
    const officerId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a61";
    const adminId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a62";

    it("resolves recipients from identityClient when recipientUserIds is omitted and emits notification:ppe_violation SSE", async () => {
      const sseCalls: Array<{ userId: string; event: any }> = [];
      const emailCalls: Array<{ to: string; data: any }> = [];
      let persistedRows: any[] = [];
      let identityLookupSite: string | undefined;

      const mockRepo = {
        findPreferencesByUserIds: async () => [],
        createManyNotifications: async (rows: any[]) => {
          persistedRows = rows;
          return { count: rows.length };
        },
      } as unknown as NotificationRepository;

      const mockMail = {
        sendPpeViolationAlertEmail: async (to: string, data: any) => {
          emailCalls.push({ to, data });
        },
      } as unknown as MailService;

      const mockSse = {
        sendToUser: (userId: string, event: any) => {
          sseCalls.push({ userId, event });
        },
      } as unknown as SseManagerService;

      const mockIncidentClient: IncidentClient = {
        getIncidentById: async () => ({ id: incidentId, siteId, cameraId }),
      };

      const mockIdentityClient: IdentityClient = {
        getIncidentRecipients: async (sid?: string) => {
          identityLookupSite = sid;
          return [
            { id: officerId, email: "officer@ppe.local", fullName: "Safety Officer", role: "SAFETY_OFFICER" },
            { id: adminId, email: "admin@ppe.local", fullName: "Admin", role: "ADMIN" },
          ];
        },
      };

      const service = new NotificationService(
        mockRepo,
        mockMail,
        mockSse,
        new EmailTemplateService(),
        mockIncidentClient,
        mockIdentityClient,
      );

      const res = await service.dispatchIncidentNotification({
        incidentId,
        siteId,
        cameraId,
        cameraCode: "CAM-01",
        violationType: "NO_HELMET",
        severity: NOTIFICATION_SEVERITY.HIGH,
        evidenceUrl: `/api/v1/incidents/evidences/${incidentId}/download`,
        referenceEvidenceUrl: `/api/v1/incidents/evidences/${cameraId}/download`,
      });

      assert.strictEqual(identityLookupSite, siteId);
      assert.strictEqual(sseCalls.length, 2);
      assert.strictEqual(sseCalls[0].event.type, "notification:ppe_violation");
      assert.strictEqual(sseCalls[0].event.data.incidentId, incidentId);
      assert.strictEqual(sseCalls[0].event.data.cameraCode, "CAM-01");
      assert.strictEqual(
        sseCalls[0].event.data.evidenceUrl,
        `/api/v1/incidents/evidences/${incidentId}/download`,
      );
      assert.strictEqual(emailCalls.length, 2);
      assert.ok(emailCalls.some((e) => e.to === "officer@ppe.local"));
      assert.ok(emailCalls.some((e) => e.to === "admin@ppe.local"));
      assert.ok(persistedRows.length >= 2);
      assert.ok(res.channels.includes(NOTIFICATION_CHANNEL.IN_APP));
    });

    it("does NOT query identityClient when explicit empty recipientUserIds: [] is supplied", async () => {
      let identityCalled = false;
      const service = new NotificationService(
        {} as NotificationRepository,
        {} as MailService,
        { sendToUser: () => {} } as unknown as SseManagerService,
        new EmailTemplateService(),
        { getIncidentById: async () => ({ id: incidentId }) },
        {
          getIncidentRecipients: async () => {
            identityCalled = true;
            return [{ id: officerId }];
          },
        },
      );

      const res = await service.dispatchIncidentNotification({
        incidentId,
        siteId,
        violationType: "NO_HELMET",
        severity: NOTIFICATION_SEVERITY.HIGH,
        recipientUserIds: [],
      });

      assert.strictEqual(identityCalled, false);
      assert.strictEqual(res.dispatchedCount, 0);
    });

    it("enforces site boundary, blocks external image injection, and ignores client email overrides on user-facing trigger", async () => {
      const siteA = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a10";
      const siteB = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a20";
      const officerA = {
        id: officerId,
        role: ROLES.SAFETY_OFFICER,
        siteId: siteA,
        siteIds: [siteA],
      };

      const sentEmails: string[] = [];
      const sseTargets: string[] = [];

      const service = new NotificationService(
        {
          findPreferencesByUserIds: async () => [],
          createManyNotifications: async (rows: any[]) => ({ count: rows.length }),
        } as unknown as NotificationRepository,
        {
          sendPpeViolationAlertEmail: async (to: string) => {
            sentEmails.push(to);
          },
        } as unknown as MailService,
        {
          sendToUser: (uid: string) => {
            sseTargets.push(uid);
          },
        } as unknown as SseManagerService,
        new EmailTemplateService(),
        {
          getIncidentById: async () => ({ id: incidentId, siteId: siteB, cameraId }),
        },
        {
          getIncidentRecipients: async (sid?: string) =>
            sid === siteB
              ? [{ id: officerId, email: "real-officer@company.vn", role: ROLES.SAFETY_OFFICER }]
              : [],
        },
      );

      // 1. Cross-site trigger (Officer from siteA triggers incident belonging to siteB) -> 403
      await assert.rejects(
        () =>
          service.dispatchIncidentNotification(
            {
              incidentId,
              violationType: "NO_HELMET",
              severity: NOTIFICATION_SEVERITY.HIGH,
            },
            officerA,
          ),
        (err: any) => err instanceof AppError && err.statusCode === 403,
      );

      // 2. Spoofed siteId different from incident.siteId -> 422
      await assert.rejects(
        () =>
          service.dispatchIncidentNotification(
            {
              incidentId,
              siteId: siteA,
              violationType: "NO_HELMET",
              severity: NOTIFICATION_SEVERITY.HIGH,
            },
            officerA,
          ),
        (err: any) => err instanceof AppError && err.statusCode === 422,
      );

      // Same-site service where incident belongs to siteA
      const siteAService = new NotificationService(
        {
          findPreferencesByUserIds: async () => [],
          createManyNotifications: async (rows: any[]) => ({ count: rows.length }),
        } as unknown as NotificationRepository,
        {
          sendPpeViolationAlertEmail: async (to: string) => {
            sentEmails.push(to);
          },
        } as unknown as MailService,
        {
          sendToUser: (uid: string) => {
            sseTargets.push(uid);
          },
        } as unknown as SseManagerService,
        new EmailTemplateService(),
        {
          getIncidentById: async () => ({ id: incidentId, siteId: siteA, cameraId }),
        },
        {
          getIncidentRecipients: async () => [
            { id: officerId, email: "real-officer@company.vn", role: ROLES.SAFETY_OFFICER },
          ],
        },
      );

      // 3. External untrusted evidenceUrl rejected on user-facing call -> 400
      await assert.rejects(
        () =>
          siteAService.dispatchIncidentNotification(
            {
              incidentId,
              siteId: siteA,
              violationType: "NO_HELMET",
              severity: NOTIFICATION_SEVERITY.HIGH,
              evidenceUrl: "https://evil.example.com/tracker.png",
            },
            officerA,
          ),
        (err: any) => err instanceof AppError && err.statusCode === 400,
      );

      // 4. Caller-supplied recipientEmails override MUST be ignored for user-facing route
      await siteAService.dispatchIncidentNotification(
        {
          incidentId,
          siteId: siteA,
          violationType: "NO_HELMET",
          severity: NOTIFICATION_SEVERITY.HIGH,
          recipientUserIds: [officerId, adminId], // adminId not in siteA recipients -> filtered out!
          recipientEmails: { [officerId]: "spoofed@evil.com" },
          evidenceUrl: `/api/v1/incidents/evidences/${incidentId}/download`,
        },
        officerA,
      );
      assert.deepStrictEqual(sseTargets, [officerId]);
      assert.deepStrictEqual(sentEmails, ["real-officer@company.vn"]);
    });

    it("isAutomatedTestRuntime does NOT trigger solely from 'test' appearing in process.argv", () => {
      const origArgv = [...process.argv];
      const origNodeEnv = process.env.NODE_ENV;
      const origCtx = process.env.NODE_TEST_CONTEXT;
      try {
        process.argv = ["node", "/opt/smart-ppe-latest/dist/server.js"];
        process.env.NODE_ENV = "production";
        delete process.env.NODE_TEST_CONTEXT;
        assert.strictEqual(isAutomatedTestRuntime(), false);
      } finally {
        process.argv = origArgv;
        if (origNodeEnv === undefined) delete process.env.NODE_ENV;
        else process.env.NODE_ENV = origNodeEnv;
        if (origCtx !== undefined) process.env.NODE_TEST_CONTEXT = origCtx;
      }
    });

    it("authMiddleware preserves siteId/siteIds from JWT onto req.user so non-admin same-site trigger succeeds", async () => {
      const siteA = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a10";
      const siteB = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a20";
      const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const origPublicKey = jwtConfig.publicKey;
      jwtConfig.publicKey = publicKey.export({ type: "spki", format: "pem" }).toString();

      try {
        const token = jwt.sign(
          {
            sub: officerId,
            email: "officer-a@company.vn",
            role: ROLES.SAFETY_OFFICER,
            siteId: siteA,
            siteIds: [siteA],
            purpose: JWT_PURPOSE.ACCESS,
          },
          privateKey,
          { algorithm: "RS256", expiresIn: "5m" },
        );

        const req: any = {
          path: "/api/v1/notifications/trigger-incident",
          originalUrl: "/api/v1/notifications/trigger-incident",
          baseUrl: "",
          query: {},
          cookies: {},
          headers: { authorization: `Bearer ${token}` },
        };

        let mwErr: any;
        await authMiddleware(req, {} as any, (err?: any) => {
          mwErr = err;
        });

        assert.strictEqual(mwErr, undefined);
        assert.strictEqual(req.user?.siteId, siteA);
        assert.deepStrictEqual(req.user?.siteIds, [siteA]);

        const sseTargets: string[] = [];
        const service = new NotificationService(
          {
            findPreferencesByUserIds: async () => [],
            createManyNotifications: async (rows: any[]) => ({ count: rows.length }),
          } as unknown as NotificationRepository,
          {
            sendPpeViolationAlertEmail: async () => {},
          } as unknown as MailService,
          {
            sendToUser: (uid: string) => {
              sseTargets.push(uid);
            },
          } as unknown as SseManagerService,
          new EmailTemplateService(),
          {
            getIncidentById: async () => ({ id: incidentId, siteId: siteA, cameraId }),
          },
          {
            getIncidentRecipients: async () => [
              { id: officerId, email: "officer-a@company.vn", role: ROLES.SAFETY_OFFICER },
            ],
          },
        );

        const res = await service.dispatchIncidentNotification(
          {
            incidentId,
            siteId: siteA,
            violationType: "NO_HELMET",
            severity: NOTIFICATION_SEVERITY.HIGH,
            evidenceUrl: `/api/v1/incidents/evidences/${incidentId}/download`,
          },
          req.user,
        );
        assert.strictEqual(res.dispatchedCount > 0, true);
        assert.deepStrictEqual(sseTargets, [officerId]);

        const crossSiteService = new NotificationService(
          {} as NotificationRepository,
          {} as MailService,
          {} as SseManagerService,
          new EmailTemplateService(),
          {
            getIncidentById: async () => ({ id: incidentId, siteId: siteB, cameraId }),
          },
          { getIncidentRecipients: async () => [] },
        );

        await assert.rejects(
          () =>
            crossSiteService.dispatchIncidentNotification(
              {
                incidentId,
                violationType: "NO_HELMET",
                severity: NOTIFICATION_SEVERITY.HIGH,
              },
              req.user,
            ),
          (err: any) => err instanceof AppError && err.statusCode === 403,
        );
      } finally {
        jwtConfig.publicKey = origPublicKey;
      }
    });
  });

  describe("Feature Flag feature.notifications.enabled & SystemConfigCacheService", () => {
    const incidentId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6b";
    const siteId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6c";
    const officerId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a61";

    it("SystemConfigCacheService fetches /system/public, caches result, and hot-toggles via Redis PubSub message", async () => {
      let fetchCalls = 0;
      let remoteEnabled = true;
      const cache = new SystemConfigCacheService(async () => {
        fetchCalls += 1;
        return {
          [FEATURE_FLAGS.NOTIFICATIONS_ENABLED]: remoteEnabled,
        };
      });

      assert.strictEqual(
        await cache.isFeatureEnabled(FEATURE_FLAGS.NOTIFICATIONS_ENABLED, true),
        true,
      );
      assert.strictEqual(fetchCalls, 1);

      // Subsequent read within TTL uses cache
      assert.strictEqual(
        await cache.isFeatureEnabled(FEATURE_FLAGS.NOTIFICATIONS_ENABLED, true),
        true,
      );
      assert.strictEqual(fetchCalls, 1);

      // Hot-toggle via Redis PubSub message with value
      cache.handlePubSubMessage(
        SYSTEM_CONFIG_PUBSUB_CHANNEL,
        JSON.stringify({
          key: FEATURE_FLAGS.NOTIFICATIONS_ENABLED,
          value: false,
        }),
      );
      assert.strictEqual(
        await cache.isFeatureEnabled(FEATURE_FLAGS.NOTIFICATIONS_ENABLED, true),
        false,
      );
      assert.strictEqual(fetchCalls, 1);

      // Invalidation without value forces re-fetch
      remoteEnabled = true;
      cache.handlePubSubMessage(
        SYSTEM_CONFIG_PUBSUB_CHANNEL,
        JSON.stringify({ key: FEATURE_FLAGS.NOTIFICATIONS_ENABLED }),
      );
      assert.strictEqual(
        await cache.isFeatureEnabled(FEATURE_FLAGS.NOTIFICATIONS_ENABLED, true),
        true,
      );
      assert.strictEqual(fetchCalls, 2);

      await cache.close();
    });

    it("SystemConfigCacheService clears expired entry and returns defaultValue when /system/public omits the key", async () => {
      let remoteConfigs: Record<string, unknown> = {
        [FEATURE_FLAGS.NOTIFICATIONS_ENABLED]: false,
      };
      let fetchCalls = 0;

      const cache = new SystemConfigCacheService(async () => {
        fetchCalls += 1;
        return remoteConfigs;
      });

      // 1. Initial fetch caches false
      assert.strictEqual(
        await cache.isFeatureEnabled(FEATURE_FLAGS.NOTIFICATIONS_ENABLED, true),
        false,
      );
      assert.strictEqual(fetchCalls, 1);

      // 2. Expire cached entry and remove key from upstream /system/public
      const internalCache = (cache as unknown as {
        cache: Map<string, { value: unknown; expiresAt: number }>;
      }).cache;
      const entry = internalCache.get(FEATURE_FLAGS.NOTIFICATIONS_ENABLED);
      assert.ok(entry);
      entry.expiresAt = Date.now() - 1000;
      remoteConfigs = {};

      // 3. Subsequent read must NOT return stale expired false; must evict and return defaultValue (true)
      assert.strictEqual(
        await cache.isFeatureEnabled(FEATURE_FLAGS.NOTIFICATIONS_ENABLED, true),
        true,
      );
      assert.strictEqual(fetchCalls, 2);
      assert.strictEqual(
        internalCache.has(FEATURE_FLAGS.NOTIFICATIONS_ENABLED),
        false,
      );

      await cache.close();
    });

    it("dispatchIncidentNotification returns 0 and sends no SSE/Email when feature.notifications.enabled is false", async () => {
      let sseCalled = false;
      let emailCalled = false;
      let persisted = false;
      let incidentLookedUp = false;

      const service = new NotificationService(
        {
          createManyNotifications: async () => {
            persisted = true;
            return { count: 1 };
          },
        } as unknown as NotificationRepository,
        {
          sendPpeViolationAlertEmail: async () => {
            emailCalled = true;
          },
        } as unknown as MailService,
        {
          sendToUser: () => {
            sseCalled = true;
          },
        } as unknown as SseManagerService,
        new EmailTemplateService(),
        {
          getIncidentById: async () => {
            incidentLookedUp = true;
            return { id: incidentId, siteId };
          },
        },
        {
          getIncidentRecipients: async () => [
            { id: officerId, email: "officer@ppe.local", role: ROLES.SAFETY_OFFICER },
          ],
        },
        { isFeatureEnabled: async () => false },
      );

      // M2M /internal/trigger-incident
      const m2mRes = await service.dispatchIncidentNotification({
        incidentId,
        siteId,
        violationType: "NO_HELMET",
        severity: NOTIFICATION_SEVERITY.HIGH,
      });
      assert.strictEqual(m2mRes.dispatchedCount, 0);
      assert.deepStrictEqual(m2mRes.channels, []);

      // User-facing /trigger-incident
      const userRes = await service.dispatchIncidentNotification(
        {
          incidentId,
          siteId,
          violationType: "NO_HELMET",
          severity: NOTIFICATION_SEVERITY.HIGH,
        },
        { id: officerId, role: ROLES.SAFETY_OFFICER, siteId, siteIds: [siteId] },
      );
      assert.strictEqual(userRes.dispatchedCount, 0);
      assert.strictEqual(sseCalled, false);
      assert.strictEqual(emailCalled, false);
      assert.strictEqual(persisted, false);
      assert.strictEqual(incidentLookedUp, false);
    });

    it("send, broadcast, and testSendTemplate reject with 403 FEATURE_DISABLED when feature.notifications.enabled is false", async () => {
      const service = new NotificationService(
        {} as NotificationRepository,
        {} as MailService,
        {} as SseManagerService,
        new EmailTemplateService(),
        undefined,
        undefined,
        { isFeatureEnabled: async () => false },
      );

      await assert.rejects(
        () =>
          service.send({
            userIds: [officerId],
            channels: [NOTIFICATION_CHANNEL.IN_APP],
            title: "Test",
            content: "Test",
          }),
        (err: any) =>
          err instanceof AppError &&
          err.statusCode === 403 &&
          err.code === ERROR_CODE.FEATURE_DISABLED,
      );

      await assert.rejects(
        () =>
          service.broadcast({
            title: "Broadcast",
            content: "Emergency",
          }),
        (err: any) =>
          err instanceof AppError &&
          err.statusCode === 403 &&
          err.code === ERROR_CODE.FEATURE_DISABLED,
      );

      await assert.rejects(
        () =>
          service.testSendTemplate("PPE_VIOLATION_ALERT", officerId, {
            variables: {},
          }),
        (err: any) =>
          err instanceof AppError &&
          err.statusCode === 403 &&
          err.code === ERROR_CODE.FEATURE_DISABLED,
      );
    });

    it("EmailWorker.process() skips claiming emails when feature.notifications.enabled is false", async () => {
      let claimed = false;
      const worker = new EmailWorker(
        { isFeatureEnabled: async () => false },
        {
          claimPendingEmails: async () => {
            claimed = true;
            return [];
          },
        } as unknown as NotificationRepository,
      );

      await worker.process();
      assert.strictEqual(claimed, false);
    });

    it("NotificationSubscriber enforces feature.notifications.enabled and user EMAIL preference on AUTH_NEW_DEVICE_DETECTED only", async () => {
      let newDeviceSent = 0;
      let verifySent = 0;
      const mockMail = {
        sendNewDeviceAlertEmail: async () => {
          newDeviceSent += 1;
        },
        sendVerificationEmail: async () => {
          verifySent += 1;
        },
      } as unknown as MailService;

      // 1. Global flag disabled -> skips AUTH_NEW_DEVICE_DETECTED, still sends verification email
      const bus1 = new EventBusService();
      const sub1 = new NotificationSubscriber(
        mockMail,
        bus1,
        { isFeatureEnabled: async () => false },
        { findUserPreferenceForChannel: async () => ({ enabled: true }) } as any,
      );
      sub1.register();
      await bus1.dispatchDirectly({
        id: "evt-nd-1",
        name: EVENT_NAMES.AUTH_NEW_DEVICE_DETECTED,
        payload: { userId: officerId, email: "officer@ppe.local", deviceName: "Edge", ip: "1.2.3.4" },
        timestamp: Date.now(),
        source: "identity",
      });
      await bus1.dispatchDirectly({
        id: "evt-ver-1",
        name: EVENT_NAMES.AUTH_USER_REGISTERED,
        payload: { userId: officerId, email: "officer@ppe.local", verifyToken: "tok" },
        timestamp: Date.now(),
        source: "identity",
      });
      assert.strictEqual(newDeviceSent, 0);
      assert.strictEqual(verifySent, 1);
      await bus1.close();

      // 2. Global flag enabled, user EMAIL preference disabled -> skips AUTH_NEW_DEVICE_DETECTED
      const bus2 = new EventBusService();
      const sub2 = new NotificationSubscriber(
        mockMail,
        bus2,
        { isFeatureEnabled: async () => true },
        { findUserPreferenceForChannel: async () => ({ enabled: false }) } as any,
      );
      sub2.register();
      await bus2.dispatchDirectly({
        id: "evt-nd-2",
        name: EVENT_NAMES.AUTH_NEW_DEVICE_DETECTED,
        payload: { userId: officerId, email: "officer@ppe.local", deviceName: "Edge", ip: "1.2.3.4" },
        timestamp: Date.now(),
        source: "identity",
      });
      assert.strictEqual(newDeviceSent, 0);
      await bus2.close();

      // 3. Both enabled -> sends AUTH_NEW_DEVICE_DETECTED
      const bus3 = new EventBusService();
      const sub3 = new NotificationSubscriber(
        mockMail,
        bus3,
        { isFeatureEnabled: async () => true },
        { findUserPreferenceForChannel: async () => ({ enabled: true }) } as any,
      );
      sub3.register();
      await bus3.dispatchDirectly({
        id: "evt-nd-3",
        name: EVENT_NAMES.AUTH_NEW_DEVICE_DETECTED,
        payload: { userId: officerId, email: "officer@ppe.local", deviceName: "Edge", ip: "1.2.3.4" },
        timestamp: Date.now(),
        source: "identity",
      });
      assert.strictEqual(newDeviceSent, 1);
      await bus3.close();
    });
  });

  describe("Incident Comment M2M Notification (notification:incident_comment)", () => {
    const incidentId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6b";
    const commentId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a77";
    const siteId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a6c";
    const adminId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a01";
    const safetyManagerId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a02";
    const managerId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a03";
    const otherOfficerId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a04";
    const assignedOfficerId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a05";
    const participantId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a06";

    it("returns dispatchedCount=0 when feature.notifications.enabled is false", async () => {
      let sseSent = false;
      const service = new NotificationService(
        {} as NotificationRepository,
        {} as MailService,
        { sendToUser: () => { sseSent = true; } } as unknown as SseManagerService,
        new EmailTemplateService(),
        undefined,
        { getIncidentRecipients: async () => [{ id: adminId, role: ROLES.ADMIN }] },
        { isFeatureEnabled: async () => false },
      );

      const res = await service.dispatchIncidentCommentNotification({
        incidentId,
        commentId,
        siteId,
        authorId: safetyManagerId,
        comment: "Kiểm tra lại mũ bảo hộ",
      });

      assert.strictEqual(res.dispatchedCount, 0);
      assert.deepStrictEqual(res.recipientUserIds, []);
      assert.strictEqual(sseSent, false);
    });

    it("merges site management + assigned + participants, excludes authorId and unrelated officers, resolves authorName, respects IN_APP preference, and emits notification:incident_comment SSE", async () => {
      const sseEvents: Array<{ userId: string; event: any }> = [];
      let persistedRows: any[] = [];

      const service = new NotificationService(
        {
          findPreferencesByUserIds: async () => [
            // managerId tắt kênh IN_APP -> phải bị lọc bỏ
            { userId: managerId, channel: NOTIFICATION_CHANNEL.IN_APP, enabled: false, severityThreshold: NOTIFICATION_SEVERITY.LOW },
            // participantId đặt ngưỡng HIGH (> NORMAL) -> phải bị lọc bỏ
            { userId: participantId, channel: NOTIFICATION_CHANNEL.IN_APP, enabled: true, severityThreshold: NOTIFICATION_SEVERITY.HIGH },
          ],
          createManyNotifications: async (rows: any[]) => {
            persistedRows = rows;
            return { count: rows.length };
          },
        } as unknown as NotificationRepository,
        {} as MailService,
        {
          sendToUser: (uid: string, event: any) => {
            sseEvents.push({ userId: uid, event });
          },
        } as unknown as SseManagerService,
        new EmailTemplateService(),
        undefined,
        {
          getIncidentRecipients: async () => [
            { id: adminId, role: ROLES.ADMIN, fullName: "Admin Hệ thống" },
            { id: safetyManagerId, role: ROLES.SAFETY_MANAGER, fullName: "Nguyễn Văn Quản Lý" },
            { id: managerId, role: ROLES.MANAGER, fullName: "Manager Site" },
            { id: otherOfficerId, role: ROLES.SAFETY_OFFICER, fullName: "Officer Ngoài Cuộc" },
          ],
        },
        { isFeatureEnabled: async () => true },
      );

      const res = await service.dispatchIncidentCommentNotification({
        incidentId,
        commentId,
        siteId,
        siteName: "Landmark 81",
        authorId: safetyManagerId,
        comment: "Công nhân   đã khắc phục chưa em?",
        assignedUserIds: [assignedOfficerId],
        participantUserIds: [participantId, safetyManagerId],
      });

      assert.strictEqual(res.dispatchedCount, 2);
      assert.deepStrictEqual(res.recipientUserIds.sort(), [adminId, assignedOfficerId].sort());
      assert.strictEqual(persistedRows.length, 2);
      assert.strictEqual(persistedRows[0].channel, NOTIFICATION_CHANNEL.IN_APP);
      assert.strictEqual(persistedRows[0].severity, NOTIFICATION_SEVERITY.NORMAL);
      assert.strictEqual(
        persistedRows[0].title,
        `Bình luận mới tại sự cố #${incidentId.slice(0, 8)} (Landmark 81)`,
      );
      assert.strictEqual(
        persistedRows[0].content,
        "[BÌNH LUẬN] Nguyễn Văn Quản Lý: Công nhân đã khắc phục chưa em?",
      );
      assert.strictEqual(sseEvents.length, 2);
      assert.strictEqual(sseEvents[0].event.type, "notification:incident_comment");
      assert.strictEqual(sseEvents[0].event.data.authorId, safetyManagerId);
      assert.strictEqual(sseEvents[0].event.data.authorName, "Nguyễn Văn Quản Lý");
    });
  });
});
