import crypto from "node:crypto";
import { envConfig } from "../../config/env.config";
import { AppError } from "../../common/errors/app-error";
import { ERROR_CODE } from "../../common/errors/error-code";
import {
  NOTIFICATION_CHANNEL,
  NOTIFICATION_SEVERITY,
  ZALO_BOT_EVENT,
  ZALO_CHAT_TYPE,
  ZALO_LINK_TOKEN_TTL_MS,
  ZALO_MAX_TEXT_LENGTH,
} from "../../common/constants/notification.constant";
import {
  isPublicHttpUrl,
  isSafeInternalEvidencePath,
  isTrustedMinioEvidenceUrl,
} from "../../common/helpers/url.helper";
import { isAutomatedTestRuntime } from "../../common/helpers/runtime.helper";
import {
  ZaloEvidenceAsset,
  ZaloEvidenceFetcher,
  defaultInternalEvidenceFetcher,
} from "./zalo-evidence.fetcher";
import {
  zaloBotClient,
  ZaloBotClient,
  ZaloBotUpdate,
  ZaloMessageResult,
  FormatPpeViolationZaloParams,
  escapeZaloMarkdown,
  formatPpeViolationZaloCaption,
  formatPpeViolationZaloMessage,
  redactBotToken,
  truncateZaloText,
} from "../../common/services/zalo-bot.client";
import {
  sseManagerService,
  SseManagerService,
} from "../../common/services/sse-manager.service";
import {
  notificationRepository,
  NotificationRepository,
} from "../notification/notification.repository";
import {
  zaloBotRepository,
  ZaloBotRepository,
  UserZaloBindingRecord,
} from "./zalo-bot.repository";
import {
  SendZaloTestDto,
  SetZaloWebhookDto,
  ZaloBotBindingDto,
  ZaloBotStatusDto,
  ZaloLinkTokenResponseDto,
} from "./zalo-bot.dto";

export type { ZaloEvidenceAsset, ZaloEvidenceFetcher };
export { defaultInternalEvidenceFetcher };

export interface PpeViolationZaloPayload extends FormatPpeViolationZaloParams {
  evidenceUrl?: string;
  referenceEvidenceUrl?: string;
  preloadedAsset?: ZaloEvidenceAsset | null;
}

export interface DispatchZaloResult {
  messageId?: string;
  method: "sendMessage" | "sendPhoto" | "mock";
  fallbackFromPhoto?: boolean;
}

export function maskChatId(chatId: string): string {
  if (!chatId) return "";
  if (chatId.length <= 8) {
    return `${chatId.slice(0, 2)}****`;
  }
  return `${chatId.slice(0, 4)}****${chatId.slice(-4)}`;
}

export function hashLinkCode(code: string): string {
  return crypto
    .createHash("sha256")
    .update(code.trim().toUpperCase(), "utf8")
    .digest("hex");
}

function extractCommand(
  rawText: string | undefined,
): { command: string; args: string[] } | null {
  if (!rawText || typeof rawText !== "string") return null;
  let cleaned = rawText.trim();
  if (!cleaned) return null;

  // Trong nhóm chat (GROUP), người dùng có thể mention "@BotName /link PPE-..." ở đầu tin nhắn
  while (/^@\S+\s*/.test(cleaned)) {
    cleaned = cleaned.replace(/^@\S+\s*/, "").trim();
  }

  if (!cleaned.startsWith("/")) {
    return null;
  }

  const parts = cleaned.split(/\s+/);
  const cmdToken = parts[0].split("@")[0].toLowerCase();
  return {
    command: cmdToken,
    args: parts.slice(1),
  };
}

const LINK_MAX_FAILURES_PER_CHAT = 5;
const LINK_FAILURE_WINDOW_MS = 10 * 60 * 1000;
const REPLY_MAX_PER_CHAT = 10;
const REPLY_WINDOW_MS = 60 * 1000;
const HINT_COOLDOWN_MS = 10 * 60 * 1000;
const MAX_TRACKER_ENTRIES = 2000;

interface SlidingWindowCounter {
  count: number;
  resetAt: number;
}

export class ZaloBotService {
  private readonly repository: ZaloBotRepository;
  private readonly client: ZaloBotClient;
  private readonly notifRepo: Pick<
    NotificationRepository,
    "findUserPreferenceForChannel" | "upsertPreference"
  >;
  private readonly sse: Pick<SseManagerService, "sendToUser">;
  private readonly evidenceFetcher: ZaloEvidenceFetcher;
  private readonly linkFailureTracker = new Map<string, SlidingWindowCounter>();
  private readonly replyRateTracker = new Map<string, SlidingWindowCounter>();
  private readonly hintCooldownTracker = new Map<string, number>();

  constructor(
    repository?: ZaloBotRepository,
    client?: ZaloBotClient,
    notifRepo?: Pick<
      NotificationRepository,
      "findUserPreferenceForChannel" | "upsertPreference"
    >,
    sse?: Pick<SseManagerService, "sendToUser">,
    evidenceFetcher?: ZaloEvidenceFetcher,
  ) {
    this.repository = repository || zaloBotRepository;
    this.client = client || zaloBotClient;
    this.notifRepo = notifRepo || notificationRepository;
    this.sse = sse || sseManagerService;
    this.evidenceFetcher = evidenceFetcher || defaultInternalEvidenceFetcher;
  }

  private pruneTrackerMap<V>(
    map: Map<string, V>,
    isExpired: (val: V, now: number) => boolean,
    now: number,
  ): void {
    if (map.size < MAX_TRACKER_ENTRIES) return;
    for (const [k, v] of map.entries()) {
      if (isExpired(v, now)) {
        map.delete(k);
      }
    }
    if (map.size >= MAX_TRACKER_ENTRIES) {
      map.clear();
    }
  }

  private isLinkRateLimited(chatId: string, now: number = Date.now()): boolean {
    const entry = this.linkFailureTracker.get(chatId);
    if (!entry) return false;
    if (now > entry.resetAt) {
      this.linkFailureTracker.delete(chatId);
      return false;
    }
    return entry.count >= LINK_MAX_FAILURES_PER_CHAT;
  }

  private recordLinkFailure(chatId: string, now: number = Date.now()): void {
    this.pruneTrackerMap(
      this.linkFailureTracker,
      (v, ts) => ts > v.resetAt,
      now,
    );
    const entry = this.linkFailureTracker.get(chatId);
    if (!entry || now > entry.resetAt) {
      this.linkFailureTracker.set(chatId, {
        count: 1,
        resetAt: now + LINK_FAILURE_WINDOW_MS,
      });
      return;
    }
    entry.count += 1;
  }

  private allowReplyForChat(chatId: string, now: number = Date.now()): boolean {
    this.pruneTrackerMap(
      this.replyRateTracker,
      (v, ts) => ts > v.resetAt,
      now,
    );
    const entry = this.replyRateTracker.get(chatId);
    if (!entry || now > entry.resetAt) {
      this.replyRateTracker.set(chatId, {
        count: 1,
        resetAt: now + REPLY_WINDOW_MS,
      });
      return true;
    }
    if (entry.count >= REPLY_MAX_PER_CHAT) {
      return false;
    }
    entry.count += 1;
    return true;
  }

  private shouldSendPrivateHint(
    chatId: string,
    now: number = Date.now(),
  ): boolean {
    this.pruneTrackerMap(
      this.hintCooldownTracker,
      (until, ts) => ts >= until,
      now,
    );
    const until = this.hintCooldownTracker.get(chatId);
    if (until && now < until) {
      return false;
    }
    this.hintCooldownTracker.set(chatId, now + HINT_COOLDOWN_MS);
    return true;
  }

  public isConfigured(): boolean {
    return this.client.isConfigured();
  }

  public verifyWebhookSecret(
    incomingHeader: unknown,
    expectedSecret: string = envConfig.zaloBot.webhookSecret,
  ): boolean {
    const secret = (expectedSecret || "").trim();
    if (!secret) {
      return false;
    }
    if (typeof incomingHeader !== "string" || incomingHeader.length === 0) {
      return false;
    }

    const incomingHash = crypto
      .createHash("sha256")
      .update(incomingHeader, "utf8")
      .digest();
    const expectedHash = crypto
      .createHash("sha256")
      .update(secret, "utf8")
      .digest();
    return crypto.timingSafeEqual(incomingHash, expectedHash);
  }

  private toBindingDto(record: UserZaloBindingRecord): ZaloBotBindingDto {
    return {
      id: record.id,
      userId: record.userId,
      chatIdMasked: maskChatId(record.chatId),
      chatType: record.chatType,
      displayName: record.displayName,
      linkedAt: record.linkedAt,
      updatedAt: record.updatedAt,
    };
  }

  private async resolveBotMeta(): Promise<{
    accountName: string | null;
    canJoinGroups: boolean;
  }> {
    const fallbackName = envConfig.zaloBot.accountName || null;
    if (!this.client.isConfigured()) {
      return { accountName: fallbackName, canJoinGroups: false };
    }
    try {
      const me = await this.client.getMe();
      return {
        accountName: me?.account_name || fallbackName,
        canJoinGroups: Boolean(me?.can_join_groups),
      };
    } catch {
      return { accountName: fallbackName, canJoinGroups: false };
    }
  }

  async findBindingByUserId(
    userId: string,
  ): Promise<UserZaloBindingRecord | null> {
    return this.repository.findBindingByUserId(userId);
  }

  async findBindingsByUserIds(
    userIds: string[],
  ): Promise<UserZaloBindingRecord[]> {
    return this.repository.findBindingsByUserIds(userIds);
  }

  // ─────────────────────────────────────────────
  // User-facing Zalo Binding & Test APIs
  // ─────────────────────────────────────────────

  async getStatus(userId: string): Promise<ZaloBotStatusDto> {
    const [binding, botMeta] = await Promise.all([
      this.repository.findBindingByUserId(userId),
      this.resolveBotMeta(),
    ]);

    return {
      botConfigured: this.client.isConfigured(),
      botMode: envConfig.zaloBot.mode,
      botAccountName: botMeta.accountName,
      canJoinGroups: botMeta.canJoinGroups,
      linked: Boolean(binding),
      binding: binding ? this.toBindingDto(binding) : null,
    };
  }

  async generateLinkToken(userId: string): Promise<ZaloLinkTokenResponseDto> {
    const code = `PPE-${crypto.randomBytes(6).toString("hex").toUpperCase()}`;
    const codeHash = hashLinkCode(code);
    const expiresAt = new Date(Date.now() + ZALO_LINK_TOKEN_TTL_MS);

    await this.repository.createLinkToken(userId, codeHash, expiresAt);
    const botMeta = await this.resolveBotMeta();

    return {
      code,
      command: `/link ${code}`,
      expiresAt,
      expiresInSeconds: Math.floor(ZALO_LINK_TOKEN_TTL_MS / 1000),
      botAccountName: botMeta.accountName,
      botConfigured: this.client.isConfigured(),
    };
  }

  async unlinkAccount(userId: string): Promise<{ unlinked: boolean }> {
    const existing = await this.repository.findBindingByUserId(userId);
    const deletedCount = await this.repository.deleteBindingByUserId(userId);

    const pref = await this.notifRepo.findUserPreferenceForChannel(
      userId,
      NOTIFICATION_CHANNEL.ZALO_BOT,
    );
    if (pref && pref.enabled) {
      await this.notifRepo.upsertPreference(
        userId,
        NOTIFICATION_CHANNEL.ZALO_BOT,
        false,
        pref.severityThreshold || NOTIFICATION_SEVERITY.HIGH,
      );
    }

    if (existing && this.client.isConfigured()) {
      await this.client
        .sendMessage({
          chatId: existing.chatId,
          parseMode: "markdown",
          text: "🔓 Tài khoản Zalo này đã được **hủy liên kết** khỏi hệ thống **Smart PPE Monitoring**.",
        })
        .catch(() => {});
    }

    if (deletedCount > 0) {
      this.sse.sendToUser(userId, {
        type: "notification:zalo_unlinked",
        data: { unlinkedAt: new Date().toISOString() },
      });
    }

    return { unlinked: deletedCount > 0 };
  }

  async sendTestMessage(
    userId: string,
    dto: SendZaloTestDto = {},
  ): Promise<{ messageId: string }> {
    if (!this.client.isConfigured()) {
      throw new AppError(
        "Zalo Bot chưa được cấu hình trên máy chủ (thiếu ZALO_BOT_TOKEN)",
        503,
        ERROR_CODE.CONFIGURATION_ERROR,
      );
    }

    const binding = await this.repository.findBindingByUserId(userId);
    if (!binding) {
      throw new AppError(
        "Bạn chưa liên kết tài khoản Zalo Bot. Vui lòng tạo mã liên kết và gửi lệnh /link tới Bot trước.",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    const customNote = dto.message?.trim()
      ? `\n- **Nội dung thử:** ${escapeZaloMarkdown(dto.message.trim())}`
      : "";

    const text = truncateZaloText(
      [
        `**✅ KIỂM TRA KẾT NỐI ZALO BOT**`,
        `- Hệ thống **Smart PPE Monitoring** đã kết nối thành công với cuộc trò chuyện này.`,
        `- **Loại hội thoại:** ${escapeZaloMarkdown(binding.chatType)}${customNote}`,
      ].join("\n"),
      ZALO_MAX_TEXT_LENGTH,
    );

    const res = await this.client.sendMessage({
      chatId: binding.chatId,
      text,
      parseMode: "markdown",
    });

    return { messageId: res.message_id };
  }

  // ─────────────────────────────────────────────
  // Incoming Update Processor (Webhook & Polling)
  // ─────────────────────────────────────────────

  private async safeReply(chatId: string, text: string): Promise<void> {
    if (!this.client.isConfigured()) return;
    if (!this.allowReplyForChat(chatId)) return;
    try {
      await this.client.sendMessage({
        chatId,
        text,
        parseMode: "markdown",
      });
    } catch (err: any) {
      console.warn(
        "[ZaloBotService] Không thể phản hồi tin nhắn Zalo:",
        redactBotToken(err?.message || String(err)),
      );
    }
  }

  async processUpdate(
    rawUpdate: unknown,
  ): Promise<{ handled: boolean; action: string }> {
    if (!rawUpdate || typeof rawUpdate !== "object") {
      return { handled: false, action: "invalid_payload" };
    }

    const update: ZaloBotUpdate =
      "result" in rawUpdate &&
      rawUpdate.result &&
      typeof rawUpdate.result === "object"
        ? (rawUpdate.result as ZaloBotUpdate)
        : (rawUpdate as ZaloBotUpdate);

    if (!update.event_name && !update.message) {
      return { handled: false, action: "webhook_probe" };
    }

    if (!update.event_name || !update.message) {
      return { handled: false, action: "missing_message" };
    }

    const msg = update.message;
    if (msg.from?.is_bot) {
      return { handled: false, action: "ignored_bot_message" };
    }

    if (update.event_name === ZALO_BOT_EVENT.MESSAGE_UNSUPPORTED) {
      return { handled: false, action: "ignored_unsupported" };
    }

    if (update.event_name !== ZALO_BOT_EVENT.MESSAGE_TEXT || typeof msg.text !== "string" || !msg.text) {
      return { handled: false, action: "ignored_non_text" };
    }

    const rawChatId = msg.chat?.id;
    const chatId = typeof rawChatId === "string" ? rawChatId.trim() : "";
    const chatType =
      msg.chat?.chat_type === ZALO_CHAT_TYPE.GROUP
        ? ZALO_CHAT_TYPE.GROUP
        : ZALO_CHAT_TYPE.PRIVATE;

    if (!chatId || chatId.length > 128) {
      return { handled: false, action: "missing_chat_id" };
    }

    const senderId =
      typeof msg.from?.id === "string" && msg.from.id.trim().length > 0
        ? msg.from.id.trim().slice(0, 128)
        : null;
    const senderDisplayName =
      typeof msg.from?.display_name === "string" &&
      msg.from.display_name.trim().length > 0
        ? msg.from.display_name.trim().slice(0, 150)
        : null;

    const parsed = extractCommand(msg.text);
    if (!parsed) {
      if (chatType === ZALO_CHAT_TYPE.PRIVATE) {
        if (!this.shouldSendPrivateHint(chatId)) {
          return { handled: false, action: "hint_throttled" };
        }
        await this.safeReply(
          chatId,
          "Xin chào! Nhắn `/help` để xem hướng dẫn hoặc `/link PPE-XXXXXXXXXXXX` để liên kết với tài khoản **Smart PPE Monitoring**.",
        );
        return { handled: true, action: "hint_sent" };
      }
      return { handled: false, action: "ignored_group_chatter" };
    }

    switch (parsed.command) {
      case "/start":
      case "/help": {
        await this.safeReply(
          chatId,
          [
            "**🤖 Smart PPE Monitoring Bot**",
            "- `/link <MÃ>`: Liên kết Zalo này với tài khoản Smart PPE để nhận cảnh báo vi phạm PPE.",
            "- `/status`: Kiểm tra trạng thái liên kết và ngưỡng cảnh báo hiện tại.",
            "- `/unlink`: Hủy liên kết nhận cảnh báo qua Zalo.",
          ].join("\n"),
        );
        return { handled: true, action: "help" };
      }

      case "/link": {
        if (this.isLinkRateLimited(chatId)) {
          return { handled: true, action: "link_rate_limited" };
        }

        const rawCode = parsed.args[0];
        if (!rawCode) {
          await this.safeReply(
            chatId,
            "{orange}Thiếu mã liên kết.{/orange} Vui lòng nhập đúng cú pháp: `/link PPE-XXXXXXXXXXXX`",
          );
          return { handled: true, action: "link_missing_code" };
        }

        const previousBinding = await this.repository.findBindingByChatId(chatId);
        if (
          previousBinding &&
          previousBinding.chatType === ZALO_CHAT_TYPE.GROUP &&
          previousBinding.zaloUserId &&
          senderId !== previousBinding.zaloUserId
        ) {
          await this.safeReply(
            chatId,
            "{orange}Nhóm này đã được liên kết bởi một tài khoản khác. Chỉ người đã liên kết mới có thể liên kết lại hoặc hủy liên kết.{/orange}",
          );
          return { handled: true, action: "link_group_owned_by_other" };
        }

        const codeHash = hashLinkCode(rawCode);
        const consumed = await this.repository.consumeLinkToken(codeHash);
        if (!consumed) {
          this.recordLinkFailure(chatId);
          await this.safeReply(
            chatId,
            "{red}Mã liên kết không hợp lệ hoặc đã hết hạn.{/red} Vui lòng tạo mã mới trên trang Cấu hình Thông báo Smart PPE.",
          );
          return { handled: true, action: "link_invalid_code" };
        }

        this.linkFailureTracker.delete(chatId);

        const binding = await this.repository.upsertBinding({
          userId: consumed.userId,
          chatId,
          chatType,
          zaloUserId: senderId,
          displayName: senderDisplayName,
        });

        if (previousBinding && previousBinding.userId !== consumed.userId) {
          const prevPref = await this.notifRepo.findUserPreferenceForChannel(
            previousBinding.userId,
            NOTIFICATION_CHANNEL.ZALO_BOT,
          );
          if (prevPref && prevPref.enabled) {
            await this.notifRepo.upsertPreference(
              previousBinding.userId,
              NOTIFICATION_CHANNEL.ZALO_BOT,
              false,
              prevPref.severityThreshold || NOTIFICATION_SEVERITY.HIGH,
            );
          }
          this.sse.sendToUser(previousBinding.userId, {
            type: "notification:zalo_unlinked",
            data: { unlinkedAt: new Date().toISOString() },
          });
        }

        const existingPref = await this.notifRepo.findUserPreferenceForChannel(
          consumed.userId,
          NOTIFICATION_CHANNEL.ZALO_BOT,
        );
        const threshold =
          existingPref?.severityThreshold || NOTIFICATION_SEVERITY.HIGH;
        await this.notifRepo.upsertPreference(
          consumed.userId,
          NOTIFICATION_CHANNEL.ZALO_BOT,
          true,
          threshold,
        );

        await this.safeReply(
          chatId,
          [
            "{green}**✅ Liên kết thành công!**{/green}",
            `- Hội thoại này đã được kết nối với **Smart PPE Monitoring** (Ngưỡng cảnh báo mặc định: **${threshold}**).`,
            `- Bạn có thể tùy chỉnh ngưỡng hoặc bật/tắt bất cứ lúc nào trên Web Console.`,
          ].join("\n"),
        );

        this.sse.sendToUser(consumed.userId, {
          type: "notification:zalo_linked",
          data: {
            binding: this.toBindingDto(binding),
            linkedAt: binding.linkedAt.toISOString(),
          },
        });

        return { handled: true, action: "linked" };
      }

      case "/unlink": {
        const existing = await this.repository.findBindingByChatId(chatId);
        if (!existing) {
          await this.safeReply(
            chatId,
            "Cuộc trò chuyện này hiện chưa được liên kết với tài khoản Smart PPE nào.",
          );
          return { handled: true, action: "unlink_not_found" };
        }

        if (
          existing.chatType === ZALO_CHAT_TYPE.GROUP &&
          existing.zaloUserId &&
          senderId !== existing.zaloUserId
        ) {
          await this.safeReply(
            chatId,
            "{orange}Chỉ người đã liên kết nhóm này mới có thể dùng lệnh /unlink (hoặc hủy liên kết trên Smart PPE Web Console).{/orange}",
          );
          return { handled: true, action: "unlink_forbidden" };
        }

        await this.repository.deleteBindingByChatId(chatId);
        const pref = await this.notifRepo.findUserPreferenceForChannel(
          existing.userId,
          NOTIFICATION_CHANNEL.ZALO_BOT,
        );
        if (pref && pref.enabled) {
          await this.notifRepo.upsertPreference(
            existing.userId,
            NOTIFICATION_CHANNEL.ZALO_BOT,
            false,
            pref.severityThreshold || NOTIFICATION_SEVERITY.HIGH,
          );
        }

        this.sse.sendToUser(existing.userId, {
          type: "notification:zalo_unlinked",
          data: { unlinkedAt: new Date().toISOString() },
        });

        await this.safeReply(
          chatId,
          "🔓 Đã **hủy liên kết** nhận cảnh báo Smart PPE cho cuộc trò chuyện này.",
        );
        return { handled: true, action: "unlinked" };
      }

      case "/status": {
        const existing = await this.repository.findBindingByChatId(chatId);
        if (!existing) {
          await this.safeReply(
            chatId,
            "Trạng thái: **Chưa liên kết**. Lấy mã trên Smart PPE Web và gửi `/link <MÃ>` để bắt đầu.",
          );
          return { handled: true, action: "status_unlinked" };
        }

        const pref = await this.notifRepo.findUserPreferenceForChannel(
          existing.userId,
          NOTIFICATION_CHANNEL.ZALO_BOT,
        );
        const enabledText = Boolean(pref?.enabled)
          ? "{green}ĐANG BẬT{/green}"
          : "{orange}ĐANG TẮT{/orange}";
        const threshold = pref?.severityThreshold || NOTIFICATION_SEVERITY.HIGH;

        await this.safeReply(
          chatId,
          [
            "**📊 Trạng thái Zalo Bot Smart PPE**",
            `- Kết nối: **Đã liên kết** (${existing.chatType})`,
            `- Trạng thái nhận tin: ${enabledText}`,
            `- Ngưỡng mức độ tối thiểu: **${threshold}**`,
          ].join("\n"),
        );
        return { handled: true, action: "status_linked" };
      }

      default:
        return { handled: false, action: "unknown_command" };
    }
  }

  // ─────────────────────────────────────────────
  // Outbound Dispatchers (Called by NotificationService)
  // ─────────────────────────────────────────────

  async dispatchPpeViolationAlert(
    chatId: string,
    data: PpeViolationZaloPayload,
  ): Promise<DispatchZaloResult> {
    if (!this.client.isConfigured()) {
      if (envConfig.nodeEnv === "production") {
        throw new AppError(
          "Dịch vụ Zalo Bot chưa được cấu hình trên môi trường production",
          503,
          ERROR_CODE.CONFIGURATION_ERROR,
        );
      }
      if (!isAutomatedTestRuntime()) {
        console.warn(
          `[ZaloBotService] DEV MODE fallback (ZALO_BOT_TOKEN chưa cấu hình) — bỏ qua gửi thật tới ${maskChatId(chatId)}`,
        );
      }
      return { method: "mock" };
    }

    const markdownText = formatPpeViolationZaloMessage(data);
    // Phương án 1: Ưu tiên ảnh vi phạm (evidenceUrl / SNAPSHOT); chỉ dùng referenceEvidenceUrl nếu thiếu evidenceUrl
    const primaryPhotoUrl = data.evidenceUrl || data.referenceEvidenceUrl;
    const plainCaption = formatPpeViolationZaloCaption(data);

    const canSendPublicPhoto = Boolean(
      primaryPhotoUrl &&
        primaryPhotoUrl.startsWith("https://") &&
        isPublicHttpUrl(primaryPhotoUrl, { allowPrivate: false }),
    );

    if (canSendPublicPhoto && primaryPhotoUrl) {
      try {
        const photoRes: ZaloMessageResult = await this.client.sendPhoto({
          chatId,
          photo: primaryPhotoUrl,
          caption: plainCaption,
        });
        return {
          messageId: photoRes.message_id,
          method: "sendPhoto",
        };
      } catch (err: any) {
        console.warn(
          `[ZaloBotService] sendPhoto (URL) thất bại, chuyển sang sendMessage fallback:`,
          redactBotToken(err?.message || String(err)),
        );
        const fallbackRes = await this.client.sendMessage({
          chatId,
          text: markdownText,
          parseMode: "markdown",
        });
        return {
          messageId: fallbackRes.message_id,
          method: "sendMessage",
          fallbackFromPhoto: true,
        };
      }
    }

    const isInternalPhotoSource = Boolean(
      primaryPhotoUrl &&
        (isSafeInternalEvidencePath(primaryPhotoUrl) ||
          isTrustedMinioEvidenceUrl(
            primaryPhotoUrl,
            envConfig.minio.endpoint,
            envConfig.minio.bucketEvidences,
          )),
    );

    if (isInternalPhotoSource && primaryPhotoUrl) {
      try {
        const asset =
          data.preloadedAsset !== undefined
            ? data.preloadedAsset
            : await this.evidenceFetcher(primaryPhotoUrl, data.incidentId);
        if (asset) {
          const photoRes: ZaloMessageResult =
            await this.client.sendPhotoBuffer({
              chatId,
              photoBuffer: asset.buffer,
              fileName: asset.fileName,
              mimeType: asset.mimeType,
              caption: plainCaption,
            });
          return {
            messageId: photoRes.message_id,
            method: "sendPhoto",
          };
        }
        console.warn(
          "[ZaloBotService] Không tải được ảnh bằng chứng nội bộ, chuyển sang sendMessage fallback",
        );
      } catch (err: any) {
        console.warn(
          `[ZaloBotService] sendPhotoBuffer thất bại, chuyển sang sendMessage fallback:`,
          redactBotToken(err?.message || String(err)),
        );
      }

      const fallbackRes = await this.client.sendMessage({
        chatId,
        text: markdownText,
        parseMode: "markdown",
      });
      return {
        messageId: fallbackRes.message_id,
        method: "sendMessage",
        fallbackFromPhoto: true,
      };
    }

    const msgRes = await this.client.sendMessage({
      chatId,
      text: markdownText,
      parseMode: "markdown",
    });
    return {
      messageId: msgRes.message_id,
      method: "sendMessage",
    };
  }

  /**
   * Tải trước đúng 1 lần binary ảnh bằng chứng nội bộ cho cả đợt phát cảnh báo tới nhiều người nhận Zalo.
   */
  async preloadEvidenceAsset(data: {
    incidentId: string;
    evidenceUrl?: string;
    referenceEvidenceUrl?: string;
  }): Promise<ZaloEvidenceAsset | null> {
    if (!this.client.isConfigured()) {
      return null;
    }
    const primaryPhotoUrl = data.evidenceUrl || data.referenceEvidenceUrl;
    if (!primaryPhotoUrl) {
      return null;
    }
    if (
      primaryPhotoUrl.startsWith("https://") &&
      isPublicHttpUrl(primaryPhotoUrl, { allowPrivate: false })
    ) {
      return null;
    }
    const isInternalPhotoSource =
      isSafeInternalEvidencePath(primaryPhotoUrl) ||
      isTrustedMinioEvidenceUrl(
        primaryPhotoUrl,
        envConfig.minio.endpoint,
        envConfig.minio.bucketEvidences,
      );
    if (!isInternalPhotoSource) {
      return null;
    }
    return this.evidenceFetcher(primaryPhotoUrl, data.incidentId);
  }

  async dispatchGenericMessage(
    chatId: string,
    params: {
      title: string;
      content: string;
      severity?: string;
      actionUrl?: string;
    },
  ): Promise<DispatchZaloResult> {
    if (!this.client.isConfigured()) {
      if (envConfig.nodeEnv === "production") {
        throw new AppError(
          "Dịch vụ Zalo Bot chưa được cấu hình trên môi trường production",
          503,
          ERROR_CODE.CONFIGURATION_ERROR,
        );
      }
      if (!isAutomatedTestRuntime()) {
        console.warn(
          `[ZaloBotService] DEV MODE fallback (ZALO_BOT_TOKEN chưa cấu hình) — bỏ qua gửi thật tới ${maskChatId(chatId)}`,
        );
      }
      return { method: "mock" };
    }

    const lines = [
      `**${escapeZaloMarkdown(params.title)}**`,
      "",
      escapeZaloMarkdown(params.content),
    ];
    if (params.actionUrl) {
      lines.push("", `🔗 ${params.actionUrl}`);
    }

    const text = truncateZaloText(lines.join("\n"), ZALO_MAX_TEXT_LENGTH);
    const res = await this.client.sendMessage({
      chatId,
      text,
      parseMode: "markdown",
    });

    return {
      messageId: res.message_id,
      method: "sendMessage",
    };
  }

  // ─────────────────────────────────────────────
  // Admin Bot & Webhook Management
  // ─────────────────────────────────────────────

  async getAdminBotInfo() {
    if (!this.client.isConfigured()) {
      throw new AppError(
        "Zalo Bot chưa được cấu hình (ZALO_BOT_TOKEN)",
        503,
        ERROR_CODE.CONFIGURATION_ERROR,
      );
    }

    const [bot, webhook] = await Promise.all([
      this.client.getMe(true),
      this.client.getWebhookInfo().catch(() => ({ url: "", updated_at: 0 })),
    ]);

    return {
      mode: envConfig.zaloBot.mode,
      bot,
      webhook,
    };
  }

  async configureWebhook(dto: SetZaloWebhookDto) {
    if (!this.client.isConfigured()) {
      throw new AppError(
        "Zalo Bot chưa được cấu hình (ZALO_BOT_TOKEN)",
        503,
        ERROR_CODE.CONFIGURATION_ERROR,
      );
    }

    const secretToken = (envConfig.zaloBot.webhookSecret || "").trim();
    const minLen = envConfig.nodeEnv === "production" ? 16 : 8;
    if (secretToken.length < minLen || secretToken.length > 256) {
      throw new AppError(
        `ZALO_BOT_WEBHOOK_SECRET chưa được cấu hình hợp lệ (cần độ dài từ ${minLen} đến 256 ký tự)`,
        400,
        ERROR_CODE.CONFIGURATION_ERROR,
      );
    }

    return this.client.setWebhook({
      url: dto.url,
      secretToken,
    });
  }

  async removeWebhook(): Promise<{ deleted: boolean }> {
    if (!this.client.isConfigured()) {
      throw new AppError(
        "Zalo Bot chưa được cấu hình (ZALO_BOT_TOKEN)",
        503,
        ERROR_CODE.CONFIGURATION_ERROR,
      );
    }
    const deleted = await this.client.deleteWebhook();
    return { deleted };
  }
}

export const zaloBotService = new ZaloBotService();
