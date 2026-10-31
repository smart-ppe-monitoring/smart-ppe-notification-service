import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { requirePermission, requireAnyPermission } from "../src/middlewares/permission.middleware";
import { authMiddleware } from "../src/middlewares/auth.middleware";
import { ROLES } from "../src/common/constants/role.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import { listEmailsSchema } from "../src/modules/notification/notification.validation";
import jwt from "jsonwebtoken";
import { jwtConfig } from "../src/config/jwt.config";

describe("Security Audit Patches - Batch 1 (SEC-01, SEC-02, SEC-03, SEC-04)", () => {
  describe("SEC-01: API Key Admin Owner Permission Scoping", () => {
    it("should allow Admin without API Key to pass any permission check", () => {
      const middleware = requirePermission(PERMISSIONS.NOTIFICATION_CREATE);
      const req: any = {
        user: { id: "admin-1", role: ROLES.ADMIN, permissions: [] },
      };
      let nextCalled = false;
      let errorThrown: any = null;

      middleware(req, {} as any, (err?: any) => {
        if (err) errorThrown = err;
        else nextCalled = true;
      });

      assert.equal(nextCalled, true);
      assert.equal(errorThrown, null);
    });

    it("should BLOCK Admin with scoped API Key lacking the required permission (SEC-01 fix)", () => {
      const middleware = requirePermission(PERMISSIONS.NOTIFICATION_CREATE);
      const req: any = {
        user: { id: "admin-1", role: ROLES.ADMIN, permissions: [] },
        apiKey: { id: "key-1", permissions: [PERMISSIONS.NOTIFICATION_READ] }, // Scoped read-only!
      };
      let nextCalled = false;
      let errorThrown: any = null;

      middleware(req, {} as any, (err?: any) => {
        if (err) errorThrown = err;
        else nextCalled = true;
      });

      assert.equal(nextCalled, false);
      assert.ok(errorThrown);
      assert.equal(errorThrown.statusCode, 403);
    });

    it("should allow Admin with scoped API Key that HAS the required permission", () => {
      const middleware = requirePermission(PERMISSIONS.NOTIFICATION_CREATE);
      const req: any = {
        user: { id: "admin-1", role: ROLES.ADMIN, permissions: [] },
        apiKey: { id: "key-1", permissions: [PERMISSIONS.NOTIFICATION_CREATE] },
      };
      let nextCalled = false;
      let errorThrown: any = null;

      middleware(req, {} as any, (err?: any) => {
        if (err) errorThrown = err;
        else nextCalled = true;
      });

      assert.equal(nextCalled, true);
      assert.equal(errorThrown, null);
    });

    it("should BLOCK Admin with scoped API Key lacking any permissions in requireAnyPermission", () => {
      const middleware = requireAnyPermission(PERMISSIONS.NOTIFICATION_CREATE, PERMISSIONS.NOTIFICATION_DELETE);
      const req: any = {
        user: { id: "admin-1", role: ROLES.ADMIN, permissions: [] },
        apiKey: { id: "key-1", permissions: [PERMISSIONS.NOTIFICATION_READ] },
      };
      let nextCalled = false;
      let errorThrown: any = null;

      middleware(req, {} as any, (err?: any) => {
        if (err) errorThrown = err;
        else nextCalled = true;
      });

      assert.equal(nextCalled, false);
      assert.ok(errorThrown);
      assert.equal(errorThrown.statusCode, 403);
    });
  });

  describe("SEC-02: 2FA Purpose Isolation Bypass", () => {
    it("should reject token with 2FA purpose on protected endpoints", async () => {
      // Mock request with 2FA verification token
      const req: any = {
        cookies: {},
        headers: {},
        path: "/api/v1/notifications",
      };

      // Mock verify to return 2FA token payload
      const origVerify = jwt.verify;
      (jwt as any).verify = () => ({
        id: "usr-1",
        role: "WORKER",
        purpose: JWT_PURPOSE.TWO_FACTOR,
      });

      const origDecode = jwt.decode;
      (jwt as any).decode = () => ({
        header: { alg: "RS256" },
      });

      req.headers.authorization = "Bearer mock-2fa-token";

      let errorThrown: any = null;
      try {
        await authMiddleware(req, {} as any, (err?: any) => {
          errorThrown = err;
        });
      } finally {
        (jwt as any).verify = origVerify;
        (jwt as any).decode = origDecode;
      }

      assert.ok(errorThrown);
      assert.equal(errorThrown.statusCode, 401);
      assert.match(errorThrown.message, /Token không hợp lệ để truy cập tài nguyên được bảo vệ/);
    });

    it("should reject token with type TEMP on protected endpoints", async () => {
      const req: any = {
        cookies: {},
        headers: {},
        path: "/api/v1/notifications",
      };

      const origVerify = jwt.verify;
      (jwt as any).verify = () => ({
        id: "usr-1",
        role: "WORKER",
        type: "TEMP",
      });

      const origDecode = jwt.decode;
      (jwt as any).decode = () => ({
        header: { alg: "RS256" },
      });

      req.headers.authorization = "Bearer mock-temp-token";

      let errorThrown: any = null;
      try {
        await authMiddleware(req, {} as any, (err?: any) => {
          errorThrown = err;
        });
      } finally {
        (jwt as any).verify = origVerify;
        (jwt as any).decode = origDecode;
      }

      assert.ok(errorThrown);
      assert.equal(errorThrown.statusCode, 401);
    });

    it("should accept valid ACCESS token", async () => {
      const req: any = {
        cookies: {},
        headers: {},
        path: "/api/v1/notifications",
      };

      const origVerify = jwt.verify;
      (jwt as any).verify = () => ({
        id: "usr-1",
        role: "WORKER",
        purpose: JWT_PURPOSE.ACCESS,
        permissions: [PERMISSIONS.NOTIFICATION_READ],
      });

      const origDecode = jwt.decode;
      (jwt as any).decode = () => ({
        header: { alg: "RS256" },
      });

      req.headers.authorization = "Bearer mock-access-token";

      let nextCalled = false;
      let errorThrown: any = null;
      try {
        await authMiddleware(req, {} as any, (err?: any) => {
          if (err) errorThrown = err;
          else nextCalled = true;
        });
      } finally {
        (jwt as any).verify = origVerify;
        (jwt as any).decode = origDecode;
      }

      assert.equal(nextCalled, true);
      assert.equal(errorThrown, null);
      assert.equal(req.user.id, "usr-1");
    });
  });

  describe("SEC-03: Email Logs BOLA & Input Validation", () => {
    it("should validate listEmailsSchema with valid pagination, status, and optional userId", () => {
      const parsed = listEmailsSchema.parse({
        page: "2",
        limit: "10",
        status: "PENDING",
        userId: "018f6e7c-8901-789a-bcde-f0123456789a",
      });

      assert.equal(parsed.page, 2);
      assert.equal(parsed.limit, 10);
      assert.equal(parsed.status, "PENDING");
      assert.equal(parsed.userId, "018f6e7c-8901-789a-bcde-f0123456789a");
    });

    it("should reject invalid status in listEmailsSchema", () => {
      assert.throws(() => {
        listEmailsSchema.parse({
          status: "UNKNOWN_STATUS",
        });
      });
    });
  });
});
