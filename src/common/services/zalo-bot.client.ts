import { envConfig } from "../../config/env.config";
import {
  NOTIFICATION_SEVERITY,
  ZALO_MAX_TEXT_LENGTH,
} from "../constants/notification.constant";
import { formatVietnamDateTime } from "../helpers/date.helper";

export interface ZaloBotMeResult {
  id: string;
  account_name: string;
  account_type?: string;
  can_join_groups?: boolean;
}

export interface ZaloMessageResult {
  message_id: string;
  date: number;
}

export interface ZaloWebhookVerificationResult {
  ok: boolean;
  url?: string;
  outcome?: string;
  hint?: string;
}

export interface ZaloWebhookSetResult {
  url: string;
  updated_at: number;
  verification?: ZaloWebhookVerificationResult;
}

export interface ZaloWebhookInfo {
  url?: string;
  updated_at?: number;
}

export interface ZaloBotChat {
  id: string;
  chat_type: "PRIVATE" | "GROUP" | string;
}

export interface ZaloBotFrom {
  id: string;
  display_name?: string;
  is_bot?: boolean;
}

export interface ZaloBotMessage {
  from: ZaloBotFrom;
  chat: ZaloBotChat;
  text?: string;
  photo?: string;
  caption?: string;
  sticker?: string;
  url?: string;
  voice_url?: string;
  message_id?: string;
  date?: number;
}

export interface ZaloBotUpdate {
  event_name: string;
  message?: ZaloBotMessage;
}

export interface ZaloApiEnvelope<T = unknown> {
  ok: boolean;
  result?: T;
  description?: string;
  error_code?: number;
  errorCode?: number;
}

export class ZaloBotApiError extends Error {
  public readonly statusCode: number;
  public readonly zaloErrorCode?: number;

  constructor(message: string, statusCode: number, zaloErrorCode?: number) {
    super(message);
    this.name = "ZaloBotApiError";
    this.statusCode = statusCode;
    this.zaloErrorCode = zaloErrorCode;
  }
}

/**
 * Ẩn hoàn toàn Bot Token khỏi thông báo lỗi, URL và log (tránh lộ credential trong URL bot<TOKEN>).
 */
export function redactBotToken(input: string, explicitToken?: string): string {
  if (!input || typeof input !== "string") return "";
  let sanitized = input.replace(/(?<!\/)\/bot[^\s/?"']+/gi, "/bot***");
  const tokenToRedact = (explicitToken ?? envConfig.zaloBot.token ?? "").trim();
  if (tokenToRedact.length > 0) {
    sanitized = sanitized.split(tokenToRedact).join("***");
  }
  return sanitized;
}

/**
 * Cắt gọn nội dung tin nhắn tuân thủ giới hạn tối đa 2000 ký tự của Zalo Bot Platform.
 */
export function truncateZaloText(
  text: string,
  maxLength: number = ZALO_MAX_TEXT_LENGTH,
): string {
  if (!text) return "";
  if (text.length <= maxLength) return text;
  if (maxLength <= 3) return text.slice(0, maxLength);
  return `${text.slice(0, maxLength - 3)}...`;
}

/**
 * Escape các ký tự đánh dấu Markdown của Zalo Bot để dữ liệu động không phá vỡ định dạng.
 */
export function escapeZaloMarkdown(text: string): string {
  return String(text || "").replace(/([*_~`{}\\])/g, "\\$1");
}

function getSeverityColorTag(severity: string): {
  open: string;
  close: string;
  label: string;
} {
  switch (severity.toUpperCase()) {
    case NOTIFICATION_SEVERITY.CRITICAL:
      return { open: "{red}", close: "{/red}", label: "KHẨN CẤP (CRITICAL)" };
    case NOTIFICATION_SEVERITY.HIGH:
      return { open: "{orange}", close: "{/orange}", label: "MỨC CAO (HIGH)" };
    case NOTIFICATION_SEVERITY.MEDIUM:
      return { open: "{yellow}", close: "{/yellow}", label: "TRUNG BÌNH (MEDIUM)" };
    case NOTIFICATION_SEVERITY.LOW:
      return { open: "{green}", close: "{/green}", label: "MỨC THẤP (LOW)" };
    default:
      return { open: "{yellow}", close: "{/yellow}", label: "BÌNH THƯỜNG (NORMAL)" };
  }
}

export interface FormatPpeViolationZaloParams {
  incidentId: string;
  violationType: string;
  severity: string;
  cameraCode?: string;
  siteName?: string;
  detectedAt?: Date | string;
  description?: string;
  appUrl?: string;
}

/**
 * Định dạng tin nhắn cảnh báo vi phạm PPE theo chuẩn Zalo Bot Rich Text (Markdown).
 */
export function formatPpeViolationZaloMessage(
  data: FormatPpeViolationZaloParams,
): string {
  const sev = getSeverityColorTag(data.severity || NOTIFICATION_SEVERITY.NORMAL);
  const detectedDate =
    data.detectedAt instanceof Date
      ? data.detectedAt
      : new Date(data.detectedAt || Date.now());
  const formattedTime = Number.isNaN(detectedDate.getTime())
    ? formatVietnamDateTime(new Date())
    : formatVietnamDateTime(detectedDate);

  const lines: string[] = [
    `**🚨 CẢNH BÁO VI PHẠM AN TOÀN PPE**`,
    `- **Mức độ:** ${sev.open}**${sev.label}**${sev.close}`,
    `- **Loại vi phạm:** ${escapeZaloMarkdown(data.violationType)}`,
    `- **Công trường:** ${escapeZaloMarkdown(data.siteName || "Công trường chính")}`,
    `- **Camera:** ${escapeZaloMarkdown(data.cameraCode || "Chưa xác định")}`,
    `- **Thời điểm:** ${escapeZaloMarkdown(formattedTime)} (UTC+7)`,
  ];

  if (data.description && data.description.trim()) {
    const safeDesc = truncateZaloText(data.description.trim(), 800);
    lines.push(`- **Chi tiết:** ${escapeZaloMarkdown(safeDesc)}`);
  }

  const baseAppUrl = (data.appUrl || envConfig.appUrl || "").replace(/\/+$/, "");
  if (baseAppUrl && data.incidentId) {
    lines.push(`- **Xem sự cố:** ${baseAppUrl}/incidents/${data.incidentId}`);
  }

  return truncateZaloText(lines.join("\n"), ZALO_MAX_TEXT_LENGTH);
}

/**
 * Định dạng caption văn bản thuần cho sendPhoto (sendPhoto không hỗ trợ parse_mode).
 */
export function formatPpeViolationZaloCaption(
  data: FormatPpeViolationZaloParams,
): string {
  const detectedDate =
    data.detectedAt instanceof Date
      ? data.detectedAt
      : new Date(data.detectedAt || Date.now());
  const formattedTime = Number.isNaN(detectedDate.getTime())
    ? formatVietnamDateTime(new Date())
    : formatVietnamDateTime(detectedDate);

  const lines: string[] = [
    `🚨 CẢNH BÁO VI PHẠM PPE [${(data.severity || "NORMAL").toUpperCase()}]`,
    `• Vi phạm: ${data.violationType}`,
    `• Công trường: ${data.siteName || "Công trường chính"}`,
    `• Camera: ${data.cameraCode || "Chưa xác định"}`,
    `• Thời điểm: ${formattedTime}`,
  ];

  if (data.description && data.description.trim()) {
    const safeDesc = truncateZaloText(data.description.trim(), 800);
    lines.push(`• Chi tiết: ${safeDesc}`);
  }

  const baseAppUrl = (data.appUrl || envConfig.appUrl || "").replace(/\/+$/, "");
  if (baseAppUrl && data.incidentId) {
    lines.push(`• Chi tiết sự cố: ${baseAppUrl}/incidents/${data.incidentId}`);
  }

  return truncateZaloText(lines.join("\n"), ZALO_MAX_TEXT_LENGTH);
}

export interface ZaloBotClientOptions {
  token?: string;
  apiBaseUrl?: string;
  fetchImpl?: typeof fetch;
}

const BOT_ME_CACHE_TTL_MS = 10 * 60 * 1000;

export class ZaloBotClient {
  private readonly tokenOverride?: string;
  private readonly apiBaseUrlOverride?: string;
  private readonly fetchImpl: typeof fetch;
  private meCache?: { expiresAt: number; data: ZaloBotMeResult };

  constructor(options: ZaloBotClientOptions = {}) {
    this.tokenOverride = options.token;
    this.apiBaseUrlOverride = options.apiBaseUrl;
    this.fetchImpl = options.fetchImpl || fetch;
  }

  private getToken(): string {
    return (this.tokenOverride ?? envConfig.zaloBot.token ?? "").trim();
  }

  private getApiBaseUrl(): string {
    return (
      this.apiBaseUrlOverride ??
      envConfig.zaloBot.apiBaseUrl ??
      "https://bot-api.zaloplatforms.com"
    )
      .trim()
      .replace(/\/+$/, "");
  }

  public isConfigured(): boolean {
    return this.getToken().length > 0;
  }

  private async callApi<T>(
    method: string,
    payload: Record<string, unknown> = {},
    options: { timeoutMs?: number; signal?: AbortSignal } = {},
  ): Promise<T> {
    const token = this.getToken();
    if (!token) {
      throw new ZaloBotApiError(
        "Zalo Bot Token chưa được cấu hình (ZALO_BOT_TOKEN)",
        503,
      );
    }

    const url = `${this.getApiBaseUrl()}/bot${token}/${method}`;
    const timeoutMs = options.timeoutMs ?? 10_000;

    const timeoutSignal = AbortSignal.timeout(timeoutMs);
    const signal = options.signal
      ? AbortSignal.any([options.signal, timeoutSignal])
      : timeoutSignal;

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          Accept: "application/json",
        },
        body: JSON.stringify(payload),
        signal,
      });
    } catch (error: any) {
      const safeMsg = redactBotToken(error?.message || String(error), token);
      throw new ZaloBotApiError(
        `Không thể kết nối tới Zalo Bot API (${method}): ${safeMsg}`,
        503,
      );
    }

    let body: ZaloApiEnvelope<T> | null = null;
    try {
      body = (await response.json()) as ZaloApiEnvelope<T>;
    } catch {
      body = null;
    }

    if (!response.ok || !body || body.ok === false) {
      const zaloCode = body?.error_code ?? body?.errorCode ?? response.status;
      const desc = redactBotToken(
        body?.description || `HTTP ${response.status}`,
        token,
      );
      throw new ZaloBotApiError(
        `Zalo Bot API lỗi (${method}) [${zaloCode}]: ${desc}`,
        response.status >= 400 ? response.status : 502,
        zaloCode,
      );
    }

    return body.result as T;
  }

  async getMe(forceRefresh = false): Promise<ZaloBotMeResult> {
    if (!forceRefresh && this.meCache && this.meCache.expiresAt > Date.now()) {
      return this.meCache.data;
    }
    const result = await this.callApi<ZaloBotMeResult>("getMe", {});
    this.meCache = {
      expiresAt: Date.now() + BOT_ME_CACHE_TTL_MS,
      data: result,
    };
    return result;
  }

  async sendMessage(params: {
    chatId: string;
    text: string;
    parseMode?: "markdown" | "html";
  }): Promise<ZaloMessageResult> {
    const body: Record<string, unknown> = {
      chat_id: params.chatId,
      text: truncateZaloText(params.text, ZALO_MAX_TEXT_LENGTH),
    };
    if (params.parseMode) {
      body.parse_mode = params.parseMode;
    }
    return this.callApi<ZaloMessageResult>("sendMessage", body);
  }

  async sendPhoto(params: {
    chatId: string;
    photo: string;
    caption?: string;
  }): Promise<ZaloMessageResult> {
    const body: Record<string, unknown> = {
      chat_id: params.chatId,
      photo: params.photo,
    };
    if (params.caption && params.caption.trim()) {
      body.caption = truncateZaloText(params.caption, ZALO_MAX_TEXT_LENGTH);
    }
    return this.callApi<ZaloMessageResult>("sendPhoto", body, {
      timeoutMs: 15_000,
    });
  }

  /**
   * Tải ảnh trực tiếp dạng multipart/form-data lên Zalo Bot API /sendPhoto
   * (dùng khi ảnh bằng chứng nằm trong mạng nội bộ / MinIO không public HTTPS).
   */
  async sendPhotoBuffer(params: {
    chatId: string;
    photoBuffer: Buffer;
    fileName?: string;
    mimeType?: string;
    caption?: string;
  }): Promise<ZaloMessageResult> {
    const token = this.getToken();
    if (!token) {
      throw new ZaloBotApiError(
        "Zalo Bot Token chưa được cấu hình (ZALO_BOT_TOKEN)",
        503,
      );
    }

    const url = `${this.getApiBaseUrl()}/bot${token}/sendPhoto`;
    const form = new FormData();
    form.append("chat_id", params.chatId);
    if (params.caption && params.caption.trim()) {
      form.append(
        "caption",
        truncateZaloText(params.caption, ZALO_MAX_TEXT_LENGTH),
      );
    }
    const mimeType = params.mimeType || "image/jpeg";
    const fileName = params.fileName || "evidence.jpg";
    form.append(
      "photo",
      new Blob([new Uint8Array(params.photoBuffer)], { type: mimeType }),
      fileName,
    );

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          Accept: "application/json",
        },
        body: form,
        signal: AbortSignal.timeout(15_000),
      });
    } catch (error: any) {
      const safeMsg = redactBotToken(error?.message || String(error), token);
      throw new ZaloBotApiError(
        `Không thể kết nối tới Zalo Bot API (sendPhoto multipart): ${safeMsg}`,
        503,
      );
    }

    let body: ZaloApiEnvelope<ZaloMessageResult> | null = null;
    try {
      body = (await response.json()) as ZaloApiEnvelope<ZaloMessageResult>;
    } catch {
      body = null;
    }

    if (!response.ok || !body || body.ok === false) {
      const zaloCode = body?.error_code ?? body?.errorCode ?? response.status;
      const desc = redactBotToken(
        body?.description || `HTTP ${response.status}`,
        token,
      );
      throw new ZaloBotApiError(
        `Zalo Bot API lỗi (sendPhoto) [${zaloCode}]: ${desc}`,
        response.status >= 400 ? response.status : 502,
        zaloCode,
      );
    }

    return body.result as ZaloMessageResult;
  }

  async setWebhook(params: {
    url: string;
    secretToken: string;
  }): Promise<ZaloWebhookSetResult> {
    return this.callApi<ZaloWebhookSetResult>("setWebhook", {
      url: params.url,
      secret_token: params.secretToken,
    });
  }

  async deleteWebhook(signal?: AbortSignal): Promise<boolean> {
    const result = await this.callApi<unknown>("deleteWebhook", {}, { signal });
    return Boolean(result ?? true);
  }

  async getWebhookInfo(): Promise<ZaloWebhookInfo> {
    return this.callApi<ZaloWebhookInfo>("getWebhookInfo", {});
  }

  async getUpdates(
    timeoutSeconds: number = envConfig.zaloBot.pollingTimeoutSeconds,
    signal?: AbortSignal,
  ): Promise<ZaloBotUpdate[]> {
    try {
      const result = await this.callApi<ZaloBotUpdate | ZaloBotUpdate[] | null>(
        "getUpdates",
        { timeout: timeoutSeconds },
        {
          timeoutMs: (timeoutSeconds + 10) * 1000,
          signal,
        },
      );

      if (!result) return [];
      if (Array.isArray(result)) {
        return result.filter((u) => u && typeof u.event_name === "string");
      }
      if (typeof result === "object" && typeof result.event_name === "string") {
        return [result];
      }
      return [];
    } catch (error) {
      if (
        error instanceof ZaloBotApiError &&
        (error.statusCode === 408 || error.zaloErrorCode === 408)
      ) {
        // 408 Request Timeout là trạng thái bình thường khi không có tin nhắn mới trong chu kỳ long-polling
        return [];
      }
      throw error;
    }
  }
}

export const zaloBotClient = new ZaloBotClient();
