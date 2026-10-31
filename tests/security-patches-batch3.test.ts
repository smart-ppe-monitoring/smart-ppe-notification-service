import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import jwt from "jsonwebtoken";
import { authMiddleware } from "../src/middlewares/auth.middleware";
import { eventBus } from "../src/common/services/event-bus.service";
import { encryptSecret, decryptSecret } from "../src/common/helpers/crypto.helper";
import { envConfig } from "../src/config/env.config";
import { ERROR_CODE } from "../src/common/errors/error-code";

describe("Security Audit Patches - Batch 3 (SEC-08, SEC-09, SEC-10, SEC-11)", () => {
  describe("SEC-08: Satellite Auth Middleware mustChangePassword Governance", () => {
    it("should reject token with mustChangePassword=true with 403 FORBIDDEN", async () => {
      const req: any = {
        cookies: {},
        headers: {
          authorization: "Bearer mock-must-change-password-token",
        },
        path: "/api/v1/notifications/preferences",
      };

      const origVerify = jwt.verify;
      const origDecode = jwt.decode;
      (jwt as any).verify = () => ({
        id: "usr-pwd-change-1",
        email: "worker@smart-ppe.local",
        role: "WORKER",
        mustChangePassword: true,
      });
      (jwt as any).decode = () => ({
        header: { alg: "RS256" },
      });

      let errorThrown: any = null;
      let nextCalled = false;
      try {
        await authMiddleware(req, {} as any, (err?: any) => {
          if (err) errorThrown = err;
          else nextCalled = true;
        });
      } finally {
        (jwt as any).verify = origVerify;
        (jwt as any).decode = origDecode;
      }

      assert.equal(nextCalled, false);
      assert.ok(errorThrown);
      assert.equal(errorThrown.statusCode, 403);
      assert.equal(errorThrown.code, ERROR_CODE.FORBIDDEN);
      assert.match(errorThrown.message, /bắt buộc phải đổi mật khẩu/);
    });

    it("should reject token with mustChangePassword='true' (string format) with 403 FORBIDDEN", async () => {
      const req: any = {
        cookies: {},
        headers: {
          authorization: "Bearer mock-must-change-password-token-str",
        },
        path: "/api/v1/notifications/preferences",
      };

      const origVerify = jwt.verify;
      const origDecode = jwt.decode;
      (jwt as any).verify = () => ({
        id: "usr-pwd-change-2",
        email: "worker2@smart-ppe.local",
        role: "WORKER",
        mustChangePassword: "true",
      });
      (jwt as any).decode = () => ({
        header: { alg: "RS256" },
      });

      let errorThrown: any = null;
      let nextCalled = false;
      try {
        await authMiddleware(req, {} as any, (err?: any) => {
          if (err) errorThrown = err;
          else nextCalled = true;
        });
      } finally {
        (jwt as any).verify = origVerify;
        (jwt as any).decode = origDecode;
      }

      assert.equal(nextCalled, false);
      assert.ok(errorThrown);
      assert.equal(errorThrown.statusCode, 403);
      assert.equal(errorThrown.code, ERROR_CODE.FORBIDDEN);
    });

    it("should allow token with mustChangePassword=false or undefined", async () => {
      const req: any = {
        cookies: {},
        headers: {
          authorization: "Bearer mock-valid-token",
        },
        path: "/api/v1/notifications/preferences",
      };

      const origVerify = jwt.verify;
      const origDecode = jwt.decode;
      (jwt as any).verify = () => ({
        id: "usr-active-1",
        email: "worker@smart-ppe.local",
        role: "WORKER",
        mustChangePassword: false,
      });
      (jwt as any).decode = () => ({
        header: { alg: "RS256" },
      });

      let errorThrown: any = null;
      let nextCalled = false;
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
      assert.equal(req.user.id, "usr-active-1");
    });
  });

  describe("SEC-09: Outbox Payload Sensitive Fields Encryption (OTP, Code, Tokens)", () => {
    it("should encrypt sensitive fields (otp, code, tempPassword, password, token, secret) with enc: prefix", () => {
      const sensitivePayload = {
        userId: "usr-sensitive-1",
        email: "target@smart-ppe.local",
        otp: "123456",
        code: "VERIFY_999",
        tempPassword: "TemporaryPassword123!",
        password: "SuperSecretPassword!",
        token: "jwt-raw-token-12345",
        secret: "totp-secret-key-xyz",
        verifyToken: "raw-verify-token",
        resetToken: "raw-reset-token",
        deactivationToken: "raw-deactivation-token",
        nonSensitiveInfo: "KeepMePlainText",
      };

      const encrypted = eventBus.encryptSensitivePayloadFields(sensitivePayload);

      // Plaintext values must be encrypted with enc: prefix
      assert.match(encrypted.otp, /^enc:/);
      assert.match(encrypted.code, /^enc:/);
      assert.match(encrypted.tempPassword, /^enc:/);
      assert.match(encrypted.password, /^enc:/);
      assert.match(encrypted.token, /^enc:/);
      assert.match(encrypted.secret, /^enc:/);
      assert.match(encrypted.verifyToken, /^enc:/);
      assert.match(encrypted.resetToken, /^enc:/);
      assert.match(encrypted.deactivationToken, /^enc:/);

      // Non-sensitive fields remain intact
      assert.equal(encrypted.userId, "usr-sensitive-1");
      assert.equal(encrypted.email, "target@smart-ppe.local");
      assert.equal(encrypted.nonSensitiveInfo, "KeepMePlainText");
    });

    it("should decrypt sensitive fields back to original values when relaying outbox events", () => {
      const originalPayload = {
        userId: "usr-sensitive-2",
        email: "target2@smart-ppe.local",
        otp: "888999",
        code: "AUTH_777",
        tempPassword: "TempPass$789!",
        verifyToken: "verify-tok-456",
      };

      const encrypted = eventBus.encryptSensitivePayloadFields(originalPayload);
      const decrypted = eventBus.decryptSensitivePayloadFields(encrypted);

      assert.equal(decrypted.otp, originalPayload.otp);
      assert.equal(decrypted.code, originalPayload.code);
      assert.equal(decrypted.tempPassword, originalPayload.tempPassword);
      assert.equal(decrypted.verifyToken, originalPayload.verifyToken);
      assert.equal(decrypted.email, originalPayload.email);
    });

    it("should not double-encrypt fields that already have enc: prefix", () => {
      const alreadyEncrypted = {
        otp: "enc:already_encrypted_string",
      };
      const result = eventBus.encryptSensitivePayloadFields(alreadyEncrypted);
      assert.equal(result.otp, "enc:already_encrypted_string");
    });
  });

  describe("SEC-10: Cryptographic Master Key Configuration & Fallback Protection", () => {
    it("should encrypt and decrypt data symmetrically with custom key", () => {
      const customKey = "my-secure-custom-key-at-least-32-chars-long";
      const plaintext = "TopSecretSensitiveData123";

      const cipher = encryptSecret(plaintext, customKey);
      assert.ok(cipher.split(":").length === 3);

      const decrypted = decryptSecret(cipher, customKey);
      assert.equal(decrypted, plaintext);
    });

    it("should encrypt and decrypt using envConfig.encryption.key", () => {
      const plaintext = "AnotherOutboxSensitivePayload";
      const cipher = encryptSecret(plaintext);
      const decrypted = decryptSecret(cipher);
      assert.equal(decrypted, plaintext);
    });

    it("should throw in production if key is insecure, default, or under 32 chars", () => {
      const origNodeEnv = (envConfig as any).nodeEnv;
      try {
        (envConfig as any).nodeEnv = "production";
        // Passing a default insecure key in production must throw
        assert.throws(() => {
          encryptSecret("sensitive", "default-smart-ppe-master-encryption-key-32b");
        }, /ENCRYPTION_KEY or APP_SECRET must be securely configured/);

        // Passing a short key (< 32 chars) in production must throw
        assert.throws(() => {
          encryptSecret("sensitive", "short_key");
        }, /ENCRYPTION_KEY or APP_SECRET must be securely configured/);
      } finally {
        (envConfig as any).nodeEnv = origNodeEnv;
      }
    });
  });

  describe("SEC-11: Database Migration Schema Synchronization (email_notifications)", () => {
    it("should have migration file defining email_notifications table and indexes", () => {
      const migrationDir = path.resolve(
        __dirname,
        "../prisma/migrations/20261031193500_add_email_notifications_table",
      );
      assert.equal(fs.existsSync(migrationDir), true);

      const migrationSqlPath = path.join(migrationDir, "migration.sql");
      assert.equal(fs.existsSync(migrationSqlPath), true);

      const sqlContent = fs.readFileSync(migrationSqlPath, "utf8");
      assert.match(sqlContent, /CREATE TABLE "email_notifications"/);
      assert.match(sqlContent, /"status" TEXT NOT NULL DEFAULT 'PENDING'/);
      assert.match(sqlContent, /"template_key" TEXT NOT NULL/);
      assert.match(
        sqlContent,
        /CREATE INDEX "email_notifications_status_attempts_idx"/,
      );
      assert.match(
        sqlContent,
        /CREATE INDEX "email_notifications_user_id_idx"/,
      );
    });

    it("should match model EmailNotification in schema.prisma", () => {
      const schemaPath = path.resolve(__dirname, "../prisma/schema.prisma");
      const schemaContent = fs.readFileSync(schemaPath, "utf8");
      assert.match(schemaContent, /model EmailNotification/);
      assert.match(schemaContent, /@@map\("email_notifications"\)/);
    });
  });
});
