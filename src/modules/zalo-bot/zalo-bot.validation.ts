import { z } from "zod";
import { isPublicHttpUrl } from "../../common/helpers/url.helper";

const DISALLOWED_ZALO_WEBHOOK_DOMAINS = [
  "zalo.me",
  "zapps.me",
  "zaloplatforms.com",
  "zaloapp.com",
  "zing.vn",
];

function isAllowedPublicWebhookUrl(rawUrl: string): boolean {
  if (!rawUrl || typeof rawUrl !== "string") return false;
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== "https:") return false;
    if (!isPublicHttpUrl(rawUrl, { allowPrivate: false })) return false;

    const host = parsed.hostname.toLowerCase().replace(/\.+$/, "");
    for (const blocked of DISALLOWED_ZALO_WEBHOOK_DOMAINS) {
      if (host === blocked || host.endsWith(`.${blocked}`)) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

const zaloWebhookMessageSchema = z
  .object({
    from: z
      .object({
        id: z.string().min(1),
        display_name: z.string().optional(),
        is_bot: z.boolean().optional(),
      })
      .passthrough(),
    chat: z
      .object({
        id: z.string().min(1),
        chat_type: z.string().min(1),
      })
      .passthrough(),
    text: z.string().optional(),
    photo: z.string().optional(),
    caption: z.string().optional(),
    sticker: z.string().optional(),
    url: z.string().optional(),
    voice_url: z.string().optional(),
    message_id: z.string().optional(),
    date: z.number().optional(),
  })
  .passthrough();

const zaloUpdatePayloadSchema = z
  .object({
    event_name: z.string().min(1, "event_name is required"),
    message: zaloWebhookMessageSchema.optional(),
  })
  .passthrough();

const zaloWebhookProbeSchema = z
  .object({
    ok: z.boolean().optional(),
  })
  .passthrough();

export const zaloWebhookUpdateSchema = z.union([
  z
    .object({
      ok: z.boolean().optional(),
      result: zaloUpdatePayloadSchema,
    })
    .passthrough(),
  zaloUpdatePayloadSchema,
  zaloWebhookProbeSchema,
]);

export const setZaloWebhookSchema = z.object({
  url: z
    .string()
    .trim()
    .url("Webhook URL không hợp lệ")
    .refine(
      (url) => isAllowedPublicWebhookUrl(url),
      "Webhook URL phải là địa chỉ HTTPS công khai hợp lệ (không dùng localhost, IP nội bộ hoặc tên miền nội bộ Zalo)",
    ),
});

export const sendZaloTestSchema = z.object({
  message: z
    .string()
    .trim()
    .min(1, "Nội dung tin nhắn thử không được để trống")
    .max(500, "Nội dung tin nhắn thử tối đa 500 ký tự")
    .optional(),
});
