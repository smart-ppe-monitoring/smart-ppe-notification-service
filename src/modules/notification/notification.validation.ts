import { z } from "zod";
import { isPublicHttpUrl } from "../../common/helpers/url.helper";
import {
  NOTIFICATION_CHANNEL,
  NOTIFICATION_SEVERITY,
  NOTIFICATION_STATUS,
} from "../../common/constants/notification.constant";

export const listNotificationsSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  isRead: z
    .string()
    .optional()
    .transform((v) =>
      v === "true" ? true : v === "false" ? false : undefined,
    ),
  status: z.enum(["PENDING", "SENT", "FAILED", "READ"]).optional(),
  severity: z.enum(["LOW", "NORMAL", "MEDIUM", "HIGH", "CRITICAL"]).optional(),
  channel: z
    .enum(["IN_APP", "WEB", "EMAIL", "ZALO_ZNS", "WEBHOOK"])
    .optional(),
  incidentId: z.string().uuid("Invalid incident ID").optional(),
  type: z.string().optional(),
  fromDate: z.string().datetime({ offset: true }).optional(),
  toDate: z.string().datetime({ offset: true }).optional(),
});

export const notificationIdParamSchema = z.object({
  id: z.string().uuid("Invalid notification ID"),
});

export const emailIdParamSchema = z.object({
  id: z.string().uuid("Invalid email ID"),
});

export const templateIdParamSchema = z.object({
  id: z.string().uuid("Invalid template ID"),
});

export const templateCodeParamSchema = z.object({
  code: z.string().min(1, "Template code is required"),
});

// ─────────────────────────────────────────────
// PPE Incident Notification Dispatch Validation
// ─────────────────────────────────────────────

export const dispatchIncidentNotificationSchema = z.object({
  incidentId: z.string().uuid("Mã sự cố incidentId không hợp lệ"),
  siteId: z.string().uuid("Mã công trường siteId không hợp lệ").optional(),
  cameraId: z.string().uuid("Mã camera cameraId không hợp lệ").optional(),
  cameraCode: z.string().optional(),
  siteName: z.string().optional(),
  violationType: z.string().min(1, "Loại vi phạm không được để trống"),
  severity: z.enum(["LOW", "NORMAL", "MEDIUM", "HIGH", "CRITICAL"], {
    errorMap: () => ({ message: "Mức độ nghiêm trọng severity không hợp lệ" }),
  }),
  description: z.string().optional(),
  evidenceUrl: z
    .string()
    .refine(
      (url) => !url || isPublicHttpUrl(url),
      "evidenceUrl phải là URL HTTP/HTTPS hợp lệ",
    )
    .optional(),
  detectedAt: z.coerce.date().optional(),
  recipientUserIds: z
    .array(z.string().uuid("Mã người dùng không hợp lệ"))
    .optional(),
  channels: z
    .array(z.enum(["IN_APP", "WEB", "EMAIL", "ZALO_ZNS", "WEBHOOK"]))
    .optional(),
});

// ─────────────────────────────────────────────
// User Notification Preference Validation
// ─────────────────────────────────────────────

export const updateNotificationPreferenceSchema = z.object({
  channel: z.enum(["IN_APP", "WEB", "EMAIL", "ZALO_ZNS", "WEBHOOK"], {
    errorMap: () => ({ message: "Kênh thông báo không hợp lệ" }),
  }),
  enabled: z.boolean({ required_error: "Trạng thái bật/tắt enabled là bắt buộc" }),
  severityThreshold: z
    .enum(["LOW", "NORMAL", "MEDIUM", "HIGH", "CRITICAL"])
    .optional()
    .default("LOW"),
});

// ─────────────────────────────────────────────
// Admin Send / Broadcast Validation
// ─────────────────────────────────────────────

export const sendNotificationSchema = z.object({
  userIds: z
    .array(z.string().uuid("Invalid user ID"))
    .min(1, "At least one userId is required"),
  channels: z
    .array(z.enum(["IN_APP", "WEB", "EMAIL", "ZALO_ZNS", "WEBHOOK"]))
    .min(1, "At least one channel is required"),
  title: z.string().min(1, "Title is required"),
  content: z.string().min(1, "Content is required"),
  severity: z
    .enum(["LOW", "NORMAL", "MEDIUM", "HIGH", "CRITICAL"])
    .optional()
    .default("NORMAL"),
  incidentId: z.string().uuid().optional(),
  type: z
    .enum(["SYSTEM", "ALERT", "INFO", "SUCCESS", "WARNING", "PPE_VIOLATION"])
    .optional(),
  priority: z.enum(["LOW", "NORMAL", "HIGH", "CRITICAL"]).optional(),
  actionUrl: z
    .string()
    .refine(
      (url) => isPublicHttpUrl(url),
      "actionUrl must be a valid public HTTPS URL (private IP and localhost are not allowed in production)",
    )
    .optional(),
  metadata: z.record(z.unknown()).optional(),
  templateKey: z.string().optional(),
  templateData: z.record(z.unknown()).optional(),
});

export const broadcastNotificationSchema = z.object({
  title: z.string().min(1, "Title is required"),
  content: z.string().min(1, "Content is required"),
  severity: z
    .enum(["LOW", "NORMAL", "MEDIUM", "HIGH", "CRITICAL"])
    .optional()
    .default("NORMAL"),
  type: z
    .enum(["SYSTEM", "ALERT", "INFO", "SUCCESS", "WARNING", "PPE_VIOLATION"])
    .optional(),
  priority: z.enum(["LOW", "NORMAL", "HIGH", "CRITICAL"]).optional(),
  actionUrl: z
    .string()
    .refine(
      (url) => isPublicHttpUrl(url),
      "actionUrl must be a valid public HTTPS URL (private IP and localhost are not allowed in production)",
    )
    .optional(),
  metadata: z.record(z.unknown()).optional(),
});

export const listEmailsSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  status: z.enum(["PENDING", "PROCESSING", "SENT", "FAILED"]).optional(),
  toEmail: z.string().optional(),
});

// ─────────────────────────────────────────────
// Notification Template Validation
// ─────────────────────────────────────────────

export const createNotificationTemplateSchema = z.object({
  code: z
    .string()
    .min(2, "Code must be at least 2 characters")
    .max(100)
    .regex(
      /^[A-Z0-9_]+$/,
      "Code must contain only uppercase letters, numbers, and underscores",
    ),
  name: z.string().min(1, "Name is required").max(255),
  channel: z
    .enum(["IN_APP", "WEB", "EMAIL", "ZALO_ZNS", "WEBHOOK"])
    .default("IN_APP"),
  subjectTemplate: z.string().nullable().optional(),
  contentTemplate: z
    .string()
    .min(1, "contentTemplate is required"),
  status: z.enum(["ACTIVE", "INACTIVE"]).default("ACTIVE"),
  // Các trường tương thích ngược
  description: z.string().max(500).optional(),
  channels: z
    .array(z.enum(["IN_APP", "WEB", "EMAIL", "ZALO_ZNS", "WEBHOOK"]))
    .optional(),
  subject: z.string().optional(),
  title: z.string().optional(),
  content: z.string().optional(),
  variables: z.array(z.string()).default([]),
  isActive: z.boolean().default(true),
});

export const updateNotificationTemplateSchema = z.object({
  name: z.string().min(1, "Name is required").max(255).optional(),
  channel: z
    .enum(["IN_APP", "WEB", "EMAIL", "ZALO_ZNS", "WEBHOOK"])
    .optional(),
  subjectTemplate: z.string().nullable().optional(),
  contentTemplate: z.string().min(1, "contentTemplate cannot be empty").optional(),
  status: z.enum(["ACTIVE", "INACTIVE"]).optional(),
  // Các trường tương thích ngược
  description: z.string().max(500).optional(),
  channels: z
    .array(z.enum(["IN_APP", "WEB", "EMAIL", "ZALO_ZNS", "WEBHOOK"]))
    .optional(),
  subject: z.string().optional(),
  title: z.string().optional(),
  content: z.string().optional(),
  variables: z.array(z.string()).optional(),
  isActive: z.boolean().optional(),
});

export const listNotificationTemplatesSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  channel: z.enum(["IN_APP", "WEB", "EMAIL", "ZALO_ZNS", "WEBHOOK"]).optional(),
  status: z.enum(["ACTIVE", "INACTIVE"]).optional(),
  isActive: z
    .string()
    .optional()
    .transform((v) =>
      v === "true" ? true : v === "false" ? false : undefined,
    ),
  search: z.string().optional(),
});

export const previewNotificationTemplateSchema = z.object({
  variables: z.record(z.unknown()).default({}),
});

export const testSendNotificationTemplateSchema = z.object({
  toEmail: z.string().email("Invalid email address").optional(),
  variables: z.record(z.unknown()).default({}),
  channels: z
    .array(z.enum(["IN_APP", "WEB", "EMAIL", "ZALO_ZNS", "WEBHOOK"]))
    .optional(),
});
