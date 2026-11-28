import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { getEventListeners } from "node:events";
import http from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import jwt from "jsonwebtoken";
import notificationApp from "../src/notification.app";
import { envConfig } from "../src/config/env.config";
import { jwtConfig } from "../src/config/jwt.config";
import { buildOpenApiSpec } from "../src/config/openapi/openapi.registry";
import { errorMiddleware } from "../src/middlewares/error.middleware";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { ROLES } from "../src/common/constants/role.constant";
import { ZaloBotPollingWorker } from "../src/common/workers/zalo-bot-polling.worker";
import {
  extractInternalEvidenceId,
  isPublicHttpUrl,
  isSafeInternalEvidencePath,
} from "../src/common/helpers/url.helper";
import {
  NOTIFICATION_CHANNEL,
  NOTIFICATION_SEVERITY,
  ZALO_BOT_EVENT,
  ZALO_CHAT_TYPE,
  ZALO_MAX_TEXT_LENGTH,
  ZALO_WEBHOOK_SECRET_HEADER,
} from "../src/common/constants/notification.constant";
import {
  ZaloBotClient,
  ZaloBotApiError,
  formatPpeViolationZaloMessage,
  redactBotToken,
  truncateZaloText,
} from "../src/common/services/zalo-bot.client";
import {
  ZaloBotService,
  hashLinkCode,
  maskChatId,
} from "../src/modules/zalo-bot/zalo-bot.service";
import { createInternalEvidenceFetcher } from "../src/modules/zalo-bot/zalo-evidence.fetcher";
import { setZaloWebhookSchema } from "../src/modules/zalo-bot/zalo-bot.validation";
import { NotificationService } from "../src/modules/notification/notification.service";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";

describe("Zalo Bot Platform Integration Suite (ZALO_BOT)", () => {
  describe("1. ZaloBotClient & Security Helpers", () => {
    it("redacts Bot Token in error messages and URLs without corrupting words containing 'bot'", () => {
      const secretToken = "123456789:secret-token-xyz";
      const raw = `ZaloBotApiError: both endpoints at https://bot-api.zaloplatforms.com/bot${secretToken}/sendMessage failed for ${secretToken}`;
      const redacted = redactBotToken(raw, secretToken);
      assert.equal(redacted.includes(secretToken), false);
      assert.equal(redacted.includes("/bot***"), true);
      assert.equal(redacted.includes("ZaloBotApiError"), true);
      assert.equal(redacted.includes("both"), true);
      assert.equal(redacted.includes("bot-api.zaloplatforms.com"), true);
    });

    it("caps long description so trailing incident URL and Markdown remain intact", () => {
      const incidentId = "11111111-1111-4111-8111-111111111111";
      const text = formatPpeViolationZaloMessage({
        incidentId,
        violationType: "NO_HELMET",
        severity: NOTIFICATION_SEVERITY.CRITICAL,
        description: "X".repeat(2500),
        appUrl: "https://ppe.example.com",
      });
      assert.ok(text.length <= ZALO_MAX_TEXT_LENGTH);
      assert.ok(text.includes(`https://ppe.example.com/incidents/${incidentId}`));
    });

    it("truncates Zalo text strictly to <= 2000 characters", () => {
      const longText = "A".repeat(2500);
      const truncated = truncateZaloText(longText, ZALO_MAX_TEXT_LENGTH);
      assert.equal(truncated.length, ZALO_MAX_TEXT_LENGTH);
      assert.ok(truncated.endsWith("..."));
    });

    it("formats PPE violation alert using Zalo Markdown and severity color tags", () => {
      const text = formatPpeViolationZaloMessage({
        incidentId: "11111111-1111-4111-8111-111111111111",
        violationType: "NO_HELMET",
        severity: NOTIFICATION_SEVERITY.CRITICAL,
        cameraCode: "CAM-01",
        siteName: "Công trường A",
        detectedAt: "2026-11-28T08:00:00.000Z",
        appUrl: "https://ppe.example.com",
      });
      assert.ok(text.includes("{red}"));
      assert.ok(text.includes("NO\\_HELMET"));
      assert.ok(text.includes("CAM-01"));
      assert.ok(text.includes("https://ppe.example.com/incidents/11111111-1111-4111-8111-111111111111"));
    });

    it("calls getMe, sendMessage, sendPhoto, setWebhook, and normalizes getUpdates (including 408 timeout)", async () => {
      const calls: Array<{ url: string; body: any }> = [];
      const token = "999999:test-bot-token";

      const mockFetch = (async (input: string | URL, init?: RequestInit) => {
        const url = String(input);
        const body =
          init?.body instanceof FormData
            ? init.body
            : init?.body
              ? JSON.parse(String(init.body))
              : {};
        calls.push({ url, body });

        if (url.endsWith("/getMe")) {
          return new Response(
            JSON.stringify({
              ok: true,
              result: {
                id: "1459232241454765289",
                account_name: "bot.SmartPPE",
                account_type: "BASIC",
                can_join_groups: true,
              },
            }),
            { status: 200 },
          );
        }
        if (url.endsWith("/sendMessage") || url.endsWith("/sendPhoto")) {
          return new Response(
            JSON.stringify({
              ok: true,
              result: { message_id: "msg_123", date: 1750000000000 },
            }),
            { status: 200 },
          );
        }
        if (url.endsWith("/setWebhook")) {
          return new Response(
            JSON.stringify({
              ok: true,
              result: {
                url: body.url,
                updated_at: 1750000000000,
                verification: { ok: true, outcome: "webhook.ok" },
              },
            }),
            { status: 200 },
          );
        }
        if (url.endsWith("/getUpdates")) {
          if (calls.filter((c) => c.url.endsWith("/getUpdates")).length === 1) {
            return new Response(
              JSON.stringify({
                ok: false,
                error_code: 408,
                description: "Request timeout",
              }),
              { status: 408 },
            );
          }
          return new Response(
            JSON.stringify({
              ok: true,
              result: {
                event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
                message: {
                  from: { id: "u1", display_name: "An" },
                  chat: { id: "c1", chat_type: "PRIVATE" },
                  text: "/status",
                },
              },
            }),
            { status: 200 },
          );
        }
        if (url.endsWith("/failEndpoint")) {
          return new Response(
            JSON.stringify({
              ok: false,
              error_code: 401,
              description: `Invalid token ${token}`,
            }),
            { status: 401 },
          );
        }
        if (url.endsWith("/testWebhookRateLimit")) {
          return new Response(
            JSON.stringify({
              ok: false,
              errorCode: 426,
              description: "Daily limit exceeded",
            }),
            { status: 429 },
          );
        }

        return new Response(JSON.stringify({ ok: true, result: {} }), { status: 200 });
      }) as typeof fetch;

      const client = new ZaloBotClient({
        token,
        apiBaseUrl: "https://bot-api.zaloplatforms.com",
        fetchImpl: mockFetch,
      });

      assert.equal(client.isConfigured(), true);
      const me = await client.getMe();
      assert.equal(me.account_name, "bot.SmartPPE");

      const msgRes = await client.sendMessage({
        chatId: "chat-1",
        text: "**Hello**",
        parseMode: "markdown",
      });
      assert.equal(msgRes.message_id, "msg_123");
      assert.equal(calls.at(-1)?.body.parse_mode, "markdown");

      const photoRes = await client.sendPhoto({
        chatId: "chat-1",
        photo: "https://cdn.example.com/snap.jpg",
        caption: "PPE Snapshot",
      });
      assert.equal(photoRes.message_id, "msg_123");

      const photoBufferRes = await client.sendPhotoBuffer({
        chatId: "chat-1",
        photoBuffer: Buffer.from([0xff, 0xd8, 0xff, 0xd9]),
        fileName: "snap.jpg",
        mimeType: "image/jpeg",
        caption: "PPE Multipart Snapshot",
      });
      assert.equal(photoBufferRes.message_id, "msg_123");
      const lastCallBody = calls.at(-1)?.body;
      assert.equal(lastCallBody instanceof FormData, true);
      assert.equal(lastCallBody.get("chat_id"), "chat-1");
      assert.equal(lastCallBody.get("caption"), "PPE Multipart Snapshot");
      assert.ok(lastCallBody.get("photo") instanceof Blob);

      const webhookRes = await client.setWebhook({
        url: "https://api.example.com/api/v1/notifications/zalo/webhook",
        secretToken: "super_secret_token_123",
      });
      assert.equal(webhookRes.verification?.ok, true);

      // Lần 1: 408 trả về mảng rỗng thay vì throw
      const emptyUpdates = await client.getUpdates(30);
      assert.deepEqual(emptyUpdates, []);

      // Lần 2: object result đơn lẻ được chuẩn hóa thành mảng 1 phần tử
      const updates = await client.getUpdates(30);
      assert.equal(updates.length, 1);
      assert.equal(updates[0].message?.text, "/status");

      // Kiểm tra lỗi không làm lộ token
      await assert.rejects(
        () => (client as any).callApi("failEndpoint", {}),
        (err: unknown) =>
          err instanceof ZaloBotApiError &&
          err.statusCode === 401 &&
          !err.message.includes(token),
      );

      // Kiểm tra parse camelCase errorCode (426 trong testWebhook)
      await assert.rejects(
        () => (client as any).callApi("testWebhookRateLimit", {}),
        (err: unknown) =>
          err instanceof ZaloBotApiError &&
          err.statusCode === 429 &&
          err.zaloErrorCode === 426,
      );
    });
  });

  describe("2. Validation Rules (setZaloWebhookSchema)", () => {
    it("accepts public HTTPS URL and rejects localhost, private IP, HTTP, and Zalo internal domains", () => {
      const ok = setZaloWebhookSchema.safeParse({
        url: "https://notify.smartppe.vn/api/v1/notifications/zalo/webhook",
      });
      assert.equal(ok.success, true);

      const rejectedUrls = [
        "http://notify.smartppe.vn/webhook",
        "https://localhost:8889/webhook",
        "https://localhost./webhook",
        "https://127.0.0.1/webhook",
        "https://192.168.1.10/webhook",
        "https://[::ffff:127.0.0.1]/webhook",
        "https://[::ffff:169.254.169.254]/latest/meta-data/",
        "https://[::ffff:10.0.0.1]/webhook",
        "https://ppe-minio.internal./webhook",
        "https://bot.zaloplatforms.com/webhook",
        "https://bot.zaloplatforms.com./webhook",
        "https://sub.zapps.me/webhook",
        "https://user:pass@notify.smartppe.vn/webhook",
      ];
      for (const badUrl of rejectedUrls) {
        const res = setZaloWebhookSchema.safeParse({ url: badUrl });
        assert.equal(res.success, false, `Should reject webhook URL: ${badUrl}`);
      }

      // SEC-ZALO-02: sendPhoto public URL guard must reject IPv4-mapped IPv6, trailing-dot internal hosts, and URLs with credentials
      for (const ssrfUrl of [
        "https://[::ffff:127.0.0.1]/img.jpg",
        "https://[::ffff:169.254.169.254]/latest/meta-data/",
        "https://[::ffff:10.0.0.1]/img.jpg",
        "https://localhost./img.jpg",
        "https://ppe-minio.internal./ppe-evidences/a.jpg",
        "https://user:pass@cdn.example.com/img.jpg",
      ]) {
        assert.equal(
          isPublicHttpUrl(ssrfUrl, { allowPrivate: false }),
          false,
          `isPublicHttpUrl should reject: ${ssrfUrl}`,
        );
      }
    });
  });

  describe("3. ZaloBotService Account Linking, Group Mention, & Unlink Flow", () => {
    function createInMemoryZaloService() {
      const bindingsByUser = new Map<string, any>();
      const tokens = new Map<string, { userId: string; expiresAt: Date; usedAt: Date | null }>();
      const prefs = new Map<string, { channel: string; enabled: boolean; severityThreshold: string }>();
      const sentMessages: Array<{ chatId: string; text: string; parseMode?: string }> = [];
      const sentPhotos: Array<{ chatId: string; photo: string; caption?: string }> = [];
      const sentPhotoBuffers: Array<{
        chatId: string;
        photoBuffer: Buffer;
        fileName?: string;
        mimeType?: string;
        caption?: string;
      }> = [];
      const fetchedUrls: string[] = [];
      const sseEvents: Array<{ userId: string; event: any }> = [];
      let failPhoto = false;
      let nextEvidenceAsset: {
        buffer: Buffer;
        mimeType: string;
        fileName: string;
      } | null = {
        buffer: Buffer.from([0xff, 0xd8, 0xff, 0xd9]),
        mimeType: "image/jpeg",
        fileName: "snapshot.jpg",
      };

      const mockRepo = {
        findBindingByUserId: async (uid: string) => bindingsByUser.get(uid) || null,
        findBindingsByUserIds: async (uids: string[]) =>
          uids.map((u) => bindingsByUser.get(u)).filter(Boolean),
        findBindingByChatId: async (chatId: string) =>
          Array.from(bindingsByUser.values()).find((b) => b.chatId === chatId) || null,
        upsertBinding: async (data: any) => {
          for (const [k, v] of bindingsByUser.entries()) {
            if (v.chatId === data.chatId && k !== data.userId) {
              bindingsByUser.delete(k);
            }
          }
          const rec = {
            id: `bind-${data.userId}`,
            userId: data.userId,
            chatId: data.chatId,
            chatType: data.chatType,
            zaloUserId: data.zaloUserId || null,
            displayName: data.displayName || null,
            linkedAt: new Date(),
            updatedAt: new Date(),
          };
          bindingsByUser.set(data.userId, rec);
          return rec;
        },
        deleteBindingByUserId: async (uid: string) => (bindingsByUser.delete(uid) ? 1 : 0),
        deleteBindingByChatId: async (chatId: string) => {
          let count = 0;
          for (const [k, v] of bindingsByUser.entries()) {
            if (v.chatId === chatId) {
              bindingsByUser.delete(k);
              count++;
            }
          }
          return count;
        },
        createLinkToken: async (userId: string, codeHash: string, expiresAt: Date) => {
          tokens.set(codeHash, { userId, expiresAt, usedAt: null });
        },
        consumeLinkToken: async (codeHash: string) => {
          const entry = tokens.get(codeHash);
          if (!entry || entry.usedAt || entry.expiresAt <= new Date()) {
            return null;
          }
          entry.usedAt = new Date();
          return { userId: entry.userId };
        },
      };

      const mockClient = {
        isConfigured: () => true,
        getMe: async () => ({
          id: "bot-id",
          account_name: "bot.SmartPPE",
          account_type: "BASIC",
          can_join_groups: true,
        }),
        sendMessage: async (p: any) => {
          sentMessages.push(p);
          return { message_id: `m-${sentMessages.length}`, date: Date.now() };
        },
        sendPhoto: async (p: any) => {
          if (failPhoto) {
            throw new ZaloBotApiError("Photo unreachable", 400);
          }
          sentPhotos.push(p);
          return { message_id: `p-${sentPhotos.length}`, date: Date.now() };
        },
        sendPhotoBuffer: async (p: any) => {
          if (failPhoto) {
            throw new ZaloBotApiError("Multipart upload failed", 400);
          }
          sentPhotoBuffers.push(p);
          return { message_id: `pb-${sentPhotoBuffers.length}`, date: Date.now() };
        },
      };

      const mockNotifRepo = {
        findUserPreferenceForChannel: async (uid: string, ch: string) =>
          prefs.get(`${uid}:${ch}`) || null,
        upsertPreference: async (uid: string, ch: string, enabled: boolean, threshold: string) => {
          const p = { channel: ch, enabled, severityThreshold: threshold };
          prefs.set(`${uid}:${ch}`, p);
          return p as any;
        },
      };

      const mockSse = {
        sendToUser: (userId: string, event: any) => {
          sseEvents.push({ userId, event });
        },
      };

      const service = new ZaloBotService(
        mockRepo as any,
        mockClient as any,
        mockNotifRepo as any,
        mockSse as any,
        async (url: string) => {
          fetchedUrls.push(url);
          return nextEvidenceAsset;
        },
      );

      return {
        service,
        bindingsByUser,
        tokens,
        prefs,
        sentMessages,
        sentPhotos,
        sentPhotoBuffers,
        fetchedUrls,
        sseEvents,
        setFailPhoto: (val: boolean) => {
          failPhoto = val;
        },
        setNextEvidenceAsset: (
          asset: { buffer: Buffer; mimeType: string; fileName: string } | null,
        ) => {
          nextEvidenceAsset = asset;
        },
      };
    }

    it("completes /link in PRIVATE chat, prevents token reuse, supports /status and /unlink", async () => {
      const ctx = createInMemoryZaloService();
      const userId = "019447e1-aaaa-7000-8000-000000000001";

      const tokenRes = await ctx.service.generateLinkToken(userId);
      assert.ok(tokenRes.code.startsWith("PPE-"));
      assert.equal(tokenRes.command, `/link ${tokenRes.code}`);

      // Gửi /link từ Zalo
      const linkOutcome = await ctx.service.processUpdate({
        ok: true,
        result: {
          event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
          message: {
            from: { id: "zalo-u1", display_name: "Nguyen Van A", is_bot: false },
            chat: { id: "zalo-chat-123456", chat_type: ZALO_CHAT_TYPE.PRIVATE },
            text: tokenRes.command,
          },
        },
      });
      assert.equal(linkOutcome.action, "linked");
      assert.equal(ctx.sseEvents.at(-1)?.event.type, "notification:zalo_linked");

      const status = await ctx.service.getStatus(userId);
      assert.equal(status.linked, true);
      assert.equal(status.binding?.chatIdMasked, maskChatId("zalo-chat-123456"));
      assert.equal(status.binding?.chatType, ZALO_CHAT_TYPE.PRIVATE);

      // Không thể tái sử dụng lại mã single-use
      const replayOutcome = await ctx.service.processUpdate({
        event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
        message: {
          from: { id: "zalo-u2", display_name: "Attacker" },
          chat: { id: "zalo-chat-evil", chat_type: ZALO_CHAT_TYPE.PRIVATE },
          text: tokenRes.command,
        },
      });
      assert.equal(replayOutcome.action, "link_invalid_code");
      assert.equal(ctx.bindingsByUser.get(userId)?.chatId, "zalo-chat-123456");

      // Test /status & sendTestMessage
      const statusCmd = await ctx.service.processUpdate({
        event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
        message: {
          from: { id: "zalo-u1" },
          chat: { id: "zalo-chat-123456", chat_type: ZALO_CHAT_TYPE.PRIVATE },
          text: "/status",
        },
      });
      assert.equal(statusCmd.action, "status_linked");

      const testRes = await ctx.service.sendTestMessage(userId, { message: "Ping" });
      assert.ok(testRes.messageId);

      // Test /unlink
      const unlinkOutcome = await ctx.service.processUpdate({
        event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
        message: {
          from: { id: "zalo-u1" },
          chat: { id: "zalo-chat-123456", chat_type: ZALO_CHAT_TYPE.PRIVATE },
          text: "/unlink",
        },
      });
      assert.equal(unlinkOutcome.action, "unlinked");
      assert.equal((await ctx.service.getStatus(userId)).linked, false);
      assert.equal(ctx.prefs.get(`${userId}:${NOTIFICATION_CHANNEL.ZALO_BOT}`)?.enabled, false);
    });

    it("supports @BotName /link CODE in GROUP chat and ignores unsupported/bot messages", async () => {
      const ctx = createInMemoryZaloService();
      const userId = "019447e1-aaaa-7000-8000-000000000002";

      const tokenRes = await ctx.service.generateLinkToken(userId);
      const groupLink = await ctx.service.processUpdate({
        event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
        message: {
          from: { id: "zalo-u2", display_name: "Truong nhom", is_bot: false },
          chat: { id: "group-chat-9999", chat_type: ZALO_CHAT_TYPE.GROUP },
          text: `@bot.SmartPPE /link ${tokenRes.code}`,
        },
      });
      assert.equal(groupLink.action, "linked");
      assert.equal(ctx.bindingsByUser.get(userId)?.chatType, ZALO_CHAT_TYPE.GROUP);

      const botMsg = await ctx.service.processUpdate({
        event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
        message: {
          from: { id: "bot-self", is_bot: true },
          chat: { id: "group-chat-9999", chat_type: ZALO_CHAT_TYPE.GROUP },
          text: "/help",
        },
      });
      assert.equal(botMsg.action, "ignored_bot_message");

      const unsupportedMsg = await ctx.service.processUpdate({
        event_name: ZALO_BOT_EVENT.MESSAGE_UNSUPPORTED,
        message: {
          from: { id: "child-account" },
          chat: { id: "private-child", chat_type: ZALO_CHAT_TYPE.PRIVATE },
        },
      });
      assert.equal(unsupportedMsg.action, "ignored_unsupported");
    });

    it("sends photo when public HTTPS URL is provided, falls back to sendMessage on photo failure, and skips photo for internal URLs", async () => {
      const ctx = createInMemoryZaloService();

      const resPhoto = await ctx.service.dispatchPpeViolationAlert("chat-1", {
        incidentId: "11111111-1111-4111-8111-111111111111",
        violationType: "NO_HELMET",
        severity: "CRITICAL",
        evidenceUrl: "https://cdn.example.com/evidences/snap.jpg",
      });
      assert.equal(resPhoto.method, "sendPhoto");
      assert.equal(ctx.sentPhotos.length, 1);

      // Internal MinIO URL -> chỉ gửi sendMessage
      const resInternal = await ctx.service.dispatchPpeViolationAlert("chat-1", {
        incidentId: "11111111-1111-4111-8111-111111111112",
        violationType: "NO_VEST",
        severity: "HIGH",
        evidenceUrl: "http://ppe-minio:9000/ppe-evidences/snap.jpg",
      });
      assert.equal(resInternal.method, "sendMessage");

      // Public URL nhưng sendPhoto lỗi -> fallback sendMessage
      ctx.setFailPhoto(true);
      const resFallback = await ctx.service.dispatchPpeViolationAlert("chat-1", {
        incidentId: "11111111-1111-4111-8111-111111111113",
        violationType: "RESTRICTED_AREA",
        severity: "CRITICAL",
        evidenceUrl: "https://cdn.example.com/evidences/broken.jpg",
      });
      assert.equal(resFallback.method, "sendMessage");
      assert.equal(resFallback.fallbackFromPhoto, true);
    });

    it("supports /api/v1/evidences/:id/download-url multipart upload (Phương án 1: prioritizes SNAPSHOT over REFERENCE_SNAPSHOT) and falls back cleanly", async () => {
      assert.equal(
        isSafeInternalEvidencePath("/api/v1/evidences/11111111-1111-4111-8111-111111111111/download-url"),
        true,
      );
      assert.equal(
        extractInternalEvidenceId("/api/v1/evidences/11111111-1111-4111-8111-111111111111/download-url"),
        "11111111-1111-4111-8111-111111111111",
      );

      const ctx = createInMemoryZaloService();
      const snapshotPath = "/api/v1/evidences/11111111-1111-4111-8111-111111111111/download-url";
      const referencePath = "/api/v1/evidences/22222222-2222-4222-8222-222222222222/download-url";

      // 1. Có cả SNAPSHOT và REFERENCE -> chỉ gửi đúng 1 ảnh (ưu tiên SNAPSHOT)
      const resBoth = await ctx.service.dispatchPpeViolationAlert("chat-1", {
        incidentId: "11111111-1111-4111-8111-111111111114",
        violationType: "NO_HELMET",
        severity: "CRITICAL",
        evidenceUrl: snapshotPath,
        referenceEvidenceUrl: referencePath,
      });
      assert.equal(resBoth.method, "sendPhoto");
      assert.equal(ctx.fetchedUrls.length, 1);
      assert.equal(ctx.fetchedUrls[0], snapshotPath);
      assert.equal(ctx.sentPhotoBuffers.length, 1);

      // 2. Chỉ có REFERENCE -> fallback dùng referenceEvidenceUrl
      const resRefOnly = await ctx.service.dispatchPpeViolationAlert("chat-1", {
        incidentId: "11111111-1111-4111-8111-111111111115",
        violationType: "NO_VEST",
        severity: "HIGH",
        referenceEvidenceUrl: referencePath,
      });
      assert.equal(resRefOnly.method, "sendPhoto");
      assert.equal(ctx.fetchedUrls.at(-1), referencePath);
      assert.equal(ctx.sentPhotoBuffers.length, 2);

      // 3. Fetcher trả về null -> fallback về sendMessage
      ctx.setNextEvidenceAsset(null);
      const resNullAsset = await ctx.service.dispatchPpeViolationAlert("chat-1", {
        incidentId: "11111111-1111-4111-8111-111111111116",
        violationType: "NO_HELMET",
        severity: "HIGH",
        evidenceUrl: snapshotPath,
      });
      assert.equal(resNullAsset.method, "sendMessage");
      assert.equal(resNullAsset.fallbackFromPhoto, true);
    });

    it("createInternalEvidenceFetcher enforces incidentId query, redirect:error, raster MIME allowlist, pre-read Content-Length cap, and safe filename decoding", async () => {
      const incidentId = "22222222-2222-4222-8222-222222222222";
      const evidencePath = "/api/v1/evidences/11111111-1111-4111-8111-111111111111/download-url";
      const origIncidentUrl = (envConfig.incident as { serviceUrl: string }).serviceUrl;
      const origInternalToken = (envConfig.internalService as { token: string }).token;
      (envConfig.incident as { serviceUrl: string }).serviceUrl = "http://incident-service:8893";
      (envConfig.internalService as { token: string }).token = "internal_test_token_1234567890123456";

      try {
        const requests: Array<{ url: string; init?: RequestInit }> = [];
        let mode: "ok" | "svg" | "oversizedHeader" | "badFilename" = "ok";
        let arrayBufferCalled = 0;

        const fetcher = createInternalEvidenceFetcher((async (input: string | URL, init?: RequestInit) => {
          requests.push({ url: String(input), init });
          if (mode === "svg") {
            return new Response("<svg/>", {
              status: 200,
              headers: { "content-type": "image/svg+xml" },
            });
          }
          if (mode === "oversizedHeader") {
            return {
              ok: true,
              status: 200,
              headers: new Headers({
                "content-type": "image/jpeg",
                "content-length": String(10 * 1024 * 1024 + 1),
              }),
              body: { cancel: async () => {} },
              arrayBuffer: async () => {
                arrayBufferCalled++;
                return new ArrayBuffer(0);
              },
            } as unknown as Response;
          }
          if (mode === "badFilename") {
            return new Response(Uint8Array.from([0xff, 0xd8, 0xff, 0xd9]), {
              status: 200,
              headers: {
                "content-type": "image/png",
                "x-evidence-filename": "%E0%A4%A",
              },
            });
          }
          return new Response(Uint8Array.from([0xff, 0xd8, 0xff, 0xd9]), {
            status: 200,
            headers: {
              "content-type": "image/jpeg",
              "x-evidence-filename": encodeURIComponent("../dir/cam01 snap.jpg"),
            },
          });
        }) as typeof fetch);

        // 1. Fail-closed khi thiếu incidentId
        assert.equal(await fetcher(evidencePath), null);
        assert.equal(requests.length, 0);

        // 2. Thành công: truyền ?incidentId=..., redirect: error, sanitize filename
        const okAsset = await fetcher(evidencePath, incidentId);
        assert.ok(okAsset);
        assert.equal(requests[0].init?.redirect, "error");
        assert.ok(requests[0].url.includes(`incidentId=${incidentId}`));
        assert.equal(okAsset.fileName, "cam01 snap.jpg");
        assert.equal(okAsset.mimeType, "image/jpeg");

        // 3. Từ chối image/svg+xml
        mode = "svg";
        assert.equal(await fetcher(evidencePath, incidentId), null);

        // 4. Từ chối Content-Length > 10MB trước khi gọi arrayBuffer()
        mode = "oversizedHeader";
        assert.equal(await fetcher(evidencePath, incidentId), null);
        assert.equal(arrayBufferCalled, 0);

        // 5. Header x-evidence-filename malformed fallback về evidence.jpg thay vì làm rơi ảnh
        mode = "badFilename";
        const fallbackNameAsset = await fetcher(evidencePath, incidentId);
        assert.ok(fallbackNameAsset);
        assert.equal(fallbackNameAsset.fileName, "evidence.jpg");
      } finally {
        (envConfig.incident as { serviceUrl: string }).serviceUrl = origIncidentUrl;
        (envConfig.internalService as { token: string }).token = origInternalToken;
      }
    });

    it("/status reports ĐANG TẮT when preference is null, GROUP /unlink blocks non-owner, and re-linking disables previous user's preference", async () => {
      const ctx = createInMemoryZaloService();
      const userA = "019447e1-aaaa-7000-8000-000000000010";
      const userB = "019447e1-aaaa-7000-8000-000000000011";

      // User A links group chat
      const tokenA = await ctx.service.generateLinkToken(userA);
      await ctx.service.processUpdate({
        event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
        message: {
          from: { id: "zalo-owner", display_name: "Owner", is_bot: false },
          chat: { id: "group-shared-1", chat_type: ZALO_CHAT_TYPE.GROUP },
          text: `/link ${tokenA.code}`,
        },
      });

      // Remove preference record to simulate missing preference row
      ctx.prefs.delete(`${userA}:${NOTIFICATION_CHANNEL.ZALO_BOT}`);
      const statusBefore = await ctx.service.processUpdate({
        event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
        message: {
          from: { id: "zalo-owner" },
          chat: { id: "group-shared-1", chat_type: ZALO_CHAT_TYPE.GROUP },
          text: "/status",
        },
      });
      assert.equal(statusBefore.action, "status_linked");
      assert.ok(ctx.sentMessages.at(-1)?.text.includes("ĐANG TẮT"));

      // Non-owner in GROUP cannot /unlink
      const nonOwnerUnlink = await ctx.service.processUpdate({
        event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
        message: {
          from: { id: "zalo-other-member" },
          chat: { id: "group-shared-1", chat_type: ZALO_CHAT_TYPE.GROUP },
          text: "/unlink",
        },
      });
      assert.equal(nonOwnerUnlink.action, "unlink_forbidden");
      assert.ok(ctx.bindingsByUser.has(userA));

      // Non-owner in GROUP cannot /link over existing group binding (SEC-ZALO-01)
      ctx.prefs.set(`${userA}:${NOTIFICATION_CHANNEL.ZALO_BOT}`, {
        channel: NOTIFICATION_CHANNEL.ZALO_BOT,
        enabled: true,
        severityThreshold: NOTIFICATION_SEVERITY.HIGH,
      });
      const tokenB = await ctx.service.generateLinkToken(userB);
      assert.match(tokenB.code, /^PPE-[A-F0-9]{12}$/);
      const hijackAttempt = await ctx.service.processUpdate({
        event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
        message: {
          from: { id: "zalo-other-member", display_name: "Attacker", is_bot: false },
          chat: { id: "group-shared-1", chat_type: ZALO_CHAT_TYPE.GROUP },
          text: `/link ${tokenB.code}`,
        },
      });
      assert.equal(hijackAttempt.action, "link_group_owned_by_other");
      assert.equal(ctx.bindingsByUser.get(userA)?.chatId, "group-shared-1");
      assert.equal(ctx.prefs.get(`${userA}:${NOTIFICATION_CHANNEL.ZALO_BOT}`)?.enabled, true);

      // Re-linking a PRIVATE chat to User B disables User A's preference & emits SSE (tokenB was not consumed by hijack attempt)
      const tokenA2 = await ctx.service.generateLinkToken(userA);
      await ctx.service.processUpdate({
        event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
        message: {
          from: { id: "zalo-private-owner", is_bot: false },
          chat: { id: "private-shared-1", chat_type: ZALO_CHAT_TYPE.PRIVATE },
          text: `/link ${tokenA2.code}`,
        },
      });
      const linkB = await ctx.service.processUpdate({
        event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
        message: {
          from: { id: "zalo-user-b", display_name: "User B", is_bot: false },
          chat: { id: "private-shared-1", chat_type: ZALO_CHAT_TYPE.PRIVATE },
          text: `/link ${tokenB.code}`,
        },
      });
      assert.equal(linkB.action, "linked");
      assert.equal(ctx.bindingsByUser.has(userA), false);
      assert.equal(ctx.prefs.get(`${userA}:${NOTIFICATION_CHANNEL.ZALO_BOT}`)?.enabled, false);
      assert.ok(
        ctx.sseEvents.some(
          (e) => e.userId === userA && e.event.type === "notification:zalo_unlinked",
        ),
      );
    });

    it("enforces per-chatId /link rate limit, private hint cooldown, oversized chatId rejection, and SHA-256 timingSafeEqual secret check", async () => {
      const ctx = createInMemoryZaloService();

      // SEC-ZALO-03: 5 failed /link attempts -> 6th hits link_rate_limited without DB lookup
      for (let i = 0; i < 5; i++) {
        const res = await ctx.service.processUpdate({
          event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
          message: {
            from: { id: "zalo-brute" },
            chat: { id: "chat-brute-1", chat_type: ZALO_CHAT_TYPE.PRIVATE },
            text: `/link PPE-INVALID0000${i}`,
          },
        });
        assert.equal(res.action, "link_invalid_code");
      }
      const blockedRes = await ctx.service.processUpdate({
        event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
        message: {
          from: { id: "zalo-brute" },
          chat: { id: "chat-brute-1", chat_type: ZALO_CHAT_TYPE.PRIVATE },
          text: "/link PPE-INVALID00099",
        },
      });
      assert.equal(blockedRes.action, "link_rate_limited");

      // SEC-ZALO-03: private chat hint sent once then throttled
      const hint1 = await ctx.service.processUpdate({
        event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
        message: {
          from: { id: "zalo-spammer" },
          chat: { id: "chat-spam-1", chat_type: ZALO_CHAT_TYPE.PRIVATE },
          text: "hello bot",
        },
      });
      assert.equal(hint1.action, "hint_sent");
      const hint2 = await ctx.service.processUpdate({
        event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
        message: {
          from: { id: "zalo-spammer" },
          chat: { id: "chat-spam-1", chat_type: ZALO_CHAT_TYPE.PRIVATE },
          text: "hello again",
        },
      });
      assert.equal(hint2.action, "hint_throttled");

      // SEC-ZALO-05: oversized or non-string chatId rejected safely
      const oversized = await ctx.service.processUpdate({
        event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
        message: {
          from: { id: "u1" },
          chat: { id: "c".repeat(129), chat_type: ZALO_CHAT_TYPE.PRIVATE },
          text: "/help",
        },
      });
      assert.equal(oversized.action, "missing_chat_id");

      // SEC-ZALO-06: verifyWebhookSecret checks across differing lengths
      assert.equal(ctx.service.verifyWebhookSecret("short", "much_longer_secret_1234"), false);
      assert.equal(ctx.service.verifyWebhookSecret("", "much_longer_secret_1234"), false);
      assert.equal(ctx.service.verifyWebhookSecret("exact_secret_1234", "exact_secret_1234"), true);
    });

    it("configureWebhook uses server envConfig.zaloBot.webhookSecret and rejects missing secret", async () => {
      const ctx = createInMemoryZaloService();
      const mutableZaloConfig = envConfig.zaloBot as { webhookSecret: string };
      const origSecret = mutableZaloConfig.webhookSecret;
      const setWebhookCalls: any[] = [];
      (ctx.service as any).client.setWebhook = async (params: any) => {
        setWebhookCalls.push(params);
        return { url: params.url, updated_at: Date.now() };
      };

      try {
        mutableZaloConfig.webhookSecret = "short";
        await assert.rejects(
          () => ctx.service.configureWebhook({ url: "https://notify.smartppe.vn/webhook" }),
          (err: any) => err instanceof AppError && err.code === ERROR_CODE.CONFIGURATION_ERROR,
        );

        mutableZaloConfig.webhookSecret = "server_managed_webhook_secret_1234";
        await ctx.service.configureWebhook({ url: "https://notify.smartppe.vn/webhook" });
        assert.equal(setWebhookCalls.length, 1);
        assert.equal(setWebhookCalls[0].secretToken, "server_managed_webhook_secret_1234");
      } finally {
        mutableZaloConfig.webhookSecret = origSecret;
      }
    });
  });

  describe("4. NotificationService Multi-Channel Dispatch with ZALO_BOT", () => {
    it("dispatches ZALO_BOT alongside IN_APP when enabled & severity >= threshold, and skips when below threshold or unlinked", async () => {
      const createdNotifications: any[] = [];
      const zaloDispatches: Array<{ chatId: string; data: any }> = [];

      const userBoundEnabled = "019447e1-bbbb-7000-8000-000000000001";
      const userBoundLowSeverity = "019447e1-bbbb-7000-8000-000000000002";
      const userUnboundEnabled = "019447e1-bbbb-7000-8000-000000000003";

      const mockRepo = {
        createManyNotifications: async (rows: any[]) => {
          createdNotifications.push(...rows);
          return { count: rows.length };
        },
        findPreferencesByUserIds: async () => [
          {
            userId: userBoundEnabled,
            channel: NOTIFICATION_CHANNEL.ZALO_BOT,
            enabled: true,
            severityThreshold: NOTIFICATION_SEVERITY.HIGH,
          },
          {
            userId: userBoundLowSeverity,
            channel: NOTIFICATION_CHANNEL.ZALO_BOT,
            enabled: true,
            severityThreshold: NOTIFICATION_SEVERITY.CRITICAL,
          },
          {
            userId: userUnboundEnabled,
            channel: NOTIFICATION_CHANNEL.ZALO_BOT,
            enabled: true,
            severityThreshold: NOTIFICATION_SEVERITY.LOW,
          },
        ],
      };

      const mockBindings = [
        {
          id: "b1",
          userId: userBoundEnabled,
          chatId: "chat-enabled-1",
          chatType: "PRIVATE",
          zaloUserId: "z1",
          displayName: "Officer 1",
          linkedAt: new Date(),
          updatedAt: new Date(),
        },
        {
          id: "b2",
          userId: userBoundLowSeverity,
          chatId: "chat-critical-only",
          chatType: "PRIVATE",
          zaloUserId: "z2",
          displayName: "Officer 2",
          linkedAt: new Date(),
          updatedAt: new Date(),
        },
      ];

      const mockZalo = {
        findBindingByUserId: async (uid: string) =>
          mockBindings.find((b) => b.userId === uid) || null,
        findBindingsByUserIds: async (uids: string[]) =>
          mockBindings.filter((b) => uids.includes(b.userId)),
        dispatchPpeViolationAlert: async (chatId: string, data: any) => {
          zaloDispatches.push({ chatId, data });
          return { method: "sendMessage" as const, messageId: "z-msg-1" };
        },
        dispatchGenericMessage: async () => ({ method: "sendMessage" as const }),
      };

      const service = new NotificationService(
        mockRepo as any,
        { sendPpeViolationAlertEmail: async () => {} } as any,
        { sendToUser: () => {} } as any,
        undefined,
        { getIncidentById: async (id: string) => ({ id, siteId: "019447e1-cccc-7000-8000-000000000001" }) },
        { getIncidentRecipients: async () => [] },
        { isFeatureEnabled: async () => true },
        mockZalo,
      );

      const res = await service.dispatchIncidentNotification({
        incidentId: "019447e1-dddd-7000-8000-000000000001",
        violationType: "NO_HELMET",
        severity: NOTIFICATION_SEVERITY.HIGH,
        cameraCode: "CAM-01",
        siteName: "Site A",
        recipientUserIds: [userBoundEnabled, userBoundLowSeverity, userUnboundEnabled],
      });

      assert.ok(res.channels.includes(NOTIFICATION_CHANNEL.ZALO_BOT));
      assert.equal(zaloDispatches.length, 1);
      assert.equal(zaloDispatches[0].chatId, "chat-enabled-1");

      const zaloRows = createdNotifications.filter(
        (n) => n.channel === NOTIFICATION_CHANNEL.ZALO_BOT,
      );
      assert.equal(zaloRows.length, 1);
      assert.equal(zaloRows[0].userId, userBoundEnabled);
    });

    it("preloads internal evidence asset once across multiple bound Zalo recipients in dispatchIncidentNotification", async () => {
      const user1 = "019447e1-ffff-7000-8000-000000000001";
      const user2 = "019447e1-ffff-7000-8000-000000000002";
      const sharedAsset = {
        buffer: Buffer.from([0xff, 0xd8, 0xff, 0xd9]),
        mimeType: "image/jpeg",
        fileName: "shared.jpg",
      };
      let preloadCalls = 0;
      const dispatchedPayloads: any[] = [];

      const service = new NotificationService(
        {
          createManyNotifications: async (rows: any[]) => ({ count: rows.length }),
          findPreferencesByUserIds: async () => [
            { userId: user1, channel: NOTIFICATION_CHANNEL.ZALO_BOT, enabled: true, severityThreshold: NOTIFICATION_SEVERITY.HIGH },
            { userId: user2, channel: NOTIFICATION_CHANNEL.ZALO_BOT, enabled: true, severityThreshold: NOTIFICATION_SEVERITY.HIGH },
          ],
        } as any,
        { sendPpeViolationAlertEmail: async () => {} } as any,
        { sendToUser: () => {} } as any,
        undefined,
        { getIncidentById: async (id: string) => ({ id, siteId: "019447e1-cccc-7000-8000-000000000002" }) },
        { getIncidentRecipients: async () => [] },
        { isFeatureEnabled: async () => true },
        {
          findBindingByUserId: async () => null,
          findBindingsByUserIds: async () => [
            { id: "b1", userId: user1, chatId: "chat-1", chatType: "PRIVATE", zaloUserId: "z1", displayName: "U1", linkedAt: new Date(), updatedAt: new Date() },
            { id: "b2", userId: user2, chatId: "chat-2", chatType: "PRIVATE", zaloUserId: "z2", displayName: "U2", linkedAt: new Date(), updatedAt: new Date() },
          ],
          preloadEvidenceAsset: async () => {
            preloadCalls++;
            return sharedAsset;
          },
          dispatchPpeViolationAlert: async (chatId: string, data: any) => {
            dispatchedPayloads.push({ chatId, data });
            return { method: "sendPhoto" as const, messageId: `m-${chatId}` };
          },
          dispatchGenericMessage: async () => ({ method: "sendMessage" as const }),
        },
      );

      await service.dispatchIncidentNotification({
        incidentId: "019447e1-dddd-7000-8000-000000000099",
        violationType: "NO_HELMET",
        severity: NOTIFICATION_SEVERITY.CRITICAL,
        evidenceUrl: "/api/v1/evidences/11111111-1111-4111-8111-111111111111/download-url",
        recipientUserIds: [user1, user2],
      });

      assert.equal(preloadCalls, 1, "Must fetch internal evidence asset once per incident dispatch");
      assert.equal(dispatchedPayloads.length, 2);
      assert.strictEqual(dispatchedPayloads[0].data.preloadedAsset, sharedAsset);
      assert.strictEqual(dispatchedPayloads[1].data.preloadedAsset, sharedAsset);
    });

    it("send() dispatches ZALO_BOT message when user has binding", async () => {
      const created: any[] = [];
      const genericCalls: any[] = [];
      const userId = "019447e1-eeee-7000-8000-000000000001";

      const service = new NotificationService(
        {
          createManyNotifications: async (rows: any[]) => {
            created.push(...rows);
            return { count: rows.length };
          },
        } as any,
        {} as any,
        { sendToUser: () => {} } as any,
        undefined,
        undefined,
        undefined,
        { isFeatureEnabled: async () => true },
        {
          findBindingByUserId: async () => null,
          findBindingsByUserIds: async () => [
            {
              id: "b1",
              userId,
              chatId: "chat-direct-1",
              chatType: "PRIVATE",
              zaloUserId: "z1",
              displayName: "Direct User",
              linkedAt: new Date(),
              updatedAt: new Date(),
            },
          ],
          dispatchPpeViolationAlert: async () => ({ method: "mock" as const }),
          dispatchGenericMessage: async (chatId, params) => {
            genericCalls.push({ chatId, params });
            return { method: "sendMessage" as const, messageId: "m-direct" };
          },
        },
      );

      const res = await service.send({
        userIds: [userId],
        channels: [NOTIFICATION_CHANNEL.ZALO_BOT],
        title: "Thông báo khẩn",
        content: "Kiểm tra khu vực B",
      });

      assert.equal(res.sentCount, 1);
      assert.equal(created[0].channel, NOTIFICATION_CHANNEL.ZALO_BOT);
      assert.equal(genericCalls.length, 1);
      assert.equal(genericCalls[0].chatId, "chat-direct-1");
    });
  });

  describe("5. HTTP Webhook Endpoint Security (X-Bot-Api-Secret-Token)", () => {
    let server: http.Server | null = null;
    let baseUrl = "";
    const mutableZaloConfig = envConfig.zaloBot as {
      webhookSecret: string;
      mode: "disabled" | "polling" | "webhook";
    };
    const origSecret = mutableZaloConfig.webhookSecret;
    const origMode = mutableZaloConfig.mode;

    before(async () => {
      server = await new Promise<http.Server>((resolve) => {
        const s = notificationApp.listen(0, "127.0.0.1", () => resolve(s));
      });
      const addr = server.address() as AddressInfo;
      baseUrl = `http://127.0.0.1:${addr.port}`;
    });

    after(async () => {
      mutableZaloConfig.webhookSecret = origSecret;
      mutableZaloConfig.mode = origMode;
      if (server) {
        await new Promise<void>((resolve) => server!.close(() => resolve()));
      }
    });

    it("rejects webhook requests when mode is disabled (503) or secret is unconfigured/mismatched (403), and accepts valid secret", async () => {
      const payload = {
        ok: true,
        result: {
          event_name: ZALO_BOT_EVENT.MESSAGE_UNSUPPORTED,
          message: {
            from: { id: "u1" },
            chat: { id: "c1", chat_type: "PRIVATE" },
          },
        },
      };

      // 0. SEC-ZALO-05: Mode disabled -> 503 kể cả khi secret khớp
      mutableZaloConfig.mode = "disabled";
      mutableZaloConfig.webhookSecret = "expected_zalo_secret_token";
      const resDisabled = await fetch(`${baseUrl}/api/v1/notifications/zalo/webhook`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [ZALO_WEBHOOK_SECRET_HEADER]: "expected_zalo_secret_token",
        },
        body: JSON.stringify(payload),
      });
      assert.equal(resDisabled.status, 503);

      // 1. Fail-closed khi chưa cấu hình secret
      mutableZaloConfig.mode = "webhook";
      mutableZaloConfig.webhookSecret = "";
      const resUnconfigured = await fetch(`${baseUrl}/api/v1/notifications/zalo/webhook`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      assert.equal(resUnconfigured.status, 403);

      // 2. Sai secret -> 403
      mutableZaloConfig.webhookSecret = "expected_zalo_secret_token";
      const resWrong = await fetch(`${baseUrl}/api/v1/notifications/zalo/webhook`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [ZALO_WEBHOOK_SECRET_HEADER]: "wrong_secret_token",
        },
        body: JSON.stringify(payload),
      });
      assert.equal(resWrong.status, 403);

      // 3. Đúng secret -> 200
      const resOk = await fetch(`${baseUrl}/api/v1/notifications/zalo/webhook`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [ZALO_WEBHOOK_SECRET_HEADER]: "expected_zalo_secret_token",
        },
        body: JSON.stringify(payload),
      });
      assert.equal(resOk.status, 200);
      const body = (await resOk.json()) as any;
      assert.equal(body.ok, true);

      // 4. Secret sai + body probe rỗng {} -> 403 trước validation (không lộ 422)
      const resWrongProbe = await fetch(`${baseUrl}/api/v1/notifications/zalo/webhook`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [ZALO_WEBHOOK_SECRET_HEADER]: "wrong_secret_token",
        },
        body: JSON.stringify({}),
      });
      assert.equal(resWrongProbe.status, 403);

      // 5. Secret đúng + probe {} từ Zalo setWebhook/testWebhook -> 200 webhook_probe
      const resOkProbe = await fetch(`${baseUrl}/api/v1/notifications/zalo/webhook`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [ZALO_WEBHOOK_SECRET_HEADER]: "expected_zalo_secret_token",
        },
        body: JSON.stringify({}),
      });
      assert.equal(resOkProbe.status, 200);
      const probeBody = (await resOkProbe.json()) as any;
      assert.equal(probeBody.data?.action, "webhook_probe");
    });

    it("does not double-decrement rate limit on /api/v1/notifications/zalo/* routes", async () => {
      const origPublicKey = jwtConfig.publicKey;
      const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      jwtConfig.publicKey = publicKey;

      try {
        const token = jwt.sign(
          {
            id: crypto.randomUUID(),
            email: "zalo-rl@smartppe.local",
            role: ROLES.SAFETY_OFFICER,
            permissions: [PERMISSIONS.NOTIFICATION_READ],
            purpose: JWT_PURPOSE.ACCESS,
            mustChangePassword: false,
          },
          privateKey,
          { algorithm: "RS256", expiresIn: "5m" },
        );

        const headers: Record<string, string> = {
          authorization: `Bearer ${token}`,
        };
        if (envConfig.gateway.internalSecret) {
          headers[GATEWAY_HEADERS.INTERNAL_SECRET] = envConfig.gateway.internalSecret;
        }

        const r1 = await fetch(`${baseUrl}/api/v1/notifications/zalo/status`, {
          headers,
        });
        const rem1 = Number(r1.headers.get("x-ratelimit-remaining"));
        const r2 = await fetch(`${baseUrl}/api/v1/notifications/zalo/status`, {
          headers,
        });
        const rem2 = Number(r2.headers.get("x-ratelimit-remaining"));
        assert.equal(rem1 - rem2, 1, "Rate limit remaining should decrement by exactly 1 per request");
      } finally {
        jwtConfig.publicKey = origPublicKey;
      }
    });
  });

  describe("6. Error Middleware Mapping, OpenAPI Generation, & Polling Worker", () => {
    it("errorMiddleware maps ZaloBotApiError to 400/429/502/503 instead of 500 and redacts tokens", async () => {
      const app = express();
      app.get("/err/:status", (req, _res, next) => {
        const st = Number(req.params.status);
        next(
          new ZaloBotApiError(
            "Call https://bot-api.zaloplatforms.com/bot12345:secret/sendMessage failed",
            st,
          ),
        );
      });
      app.use(errorMiddleware);

      const s = await new Promise<http.Server>((resolve) => {
        const srv = app.listen(0, "127.0.0.1", () => resolve(srv));
      });
      try {
        const addr = s.address() as AddressInfo;
        const base = `http://127.0.0.1:${addr.port}`;

        const r400 = await fetch(`${base}/err/400`);
        assert.equal(r400.status, 400);
        const body400 = (await r400.json()) as any;
        assert.equal(body400.message.includes("12345:secret"), false);

        const r401 = await fetch(`${base}/err/401`);
        assert.equal(r401.status, 502);

        const r429 = await fetch(`${base}/err/429`);
        assert.equal(r429.status, 429);

        const r503 = await fetch(`${base}/err/503`);
        assert.equal(r503.status, 503);
      } finally {
        await new Promise<void>((resolve) => s.close(() => resolve()));
      }
    });

    it("buildOpenApiSpec() includes Zalo Bot paths cleanly", () => {
      const spec = buildOpenApiSpec();
      assert.ok(spec.paths["/notifications/zalo/status"]);
      assert.ok(spec.paths["/notifications/zalo/webhook"]);
      assert.ok(spec.paths["/notifications/zalo/admin/webhook"]);
    });

    it("ZaloBotPollingWorker cleans up webhook, processes updates, backs off without leaking abort listeners, and stops cleanly", async () => {
      let deleteWebhookCalls = 0;
      let getUpdatesCount = 0;
      const processed: any[] = [];

      const mockClient = {
        isConfigured: () => true,
        deleteWebhook: async () => {
          deleteWebhookCalls++;
          return true;
        },
        getUpdates: async () => {
          getUpdatesCount++;
          if (getUpdatesCount === 1) {
            throw new Error("temporary network glitch");
          }
          if (getUpdatesCount === 2) {
            return [
              {
                event_name: ZALO_BOT_EVENT.MESSAGE_TEXT,
                message: {
                  from: { id: "u1" },
                  chat: { id: "c1", chat_type: "PRIVATE" },
                  text: "/help",
                },
              },
            ];
          }
          await new Promise((r) => setTimeout(r, 50));
          return [];
        },
      };

      const mockService = {
        processUpdate: async (u: any) => {
          processed.push(u);
          return { handled: true, action: "help" };
        },
      };

      const worker = new ZaloBotPollingWorker(
        mockClient as any,
        mockService as any,
        {
          allowInTest: true,
          backoffScheduleMs: [10],
          pollingTimeoutSeconds: 5,
        },
      );

      worker.start();
      const signal = (worker as any).abortController?.signal as AbortSignal;
      assert.ok(signal);

      // Wait until retry backoff finishes and update #2 is processed
      await new Promise((r) => setTimeout(r, 80));
      assert.equal(deleteWebhookCalls, 1);
      assert.equal(processed.length, 1);
      // No leaked abort listeners after sleepWithAbort completes normally
      assert.equal(getEventListeners(signal, "abort").length, 0);

      await worker.stop();
    });
  });

  it("hashLinkCode normalizes case and whitespace consistently", () => {
    assert.equal(hashLinkCode("ppe-12ab34cd"), hashLinkCode("  PPE-12AB34CD  "));
  });
});
