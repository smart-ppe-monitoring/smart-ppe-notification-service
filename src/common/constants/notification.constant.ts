export const NOTIFICATION_TYPE = {
  SYSTEM: "SYSTEM",
  ALERT: "ALERT",
  INFO: "INFO",
  SUCCESS: "SUCCESS",
  WARNING: "WARNING",
  PPE_VIOLATION: "PPE_VIOLATION",
} as const;

/** UUID định danh đặc biệt đại diện cho thông báo toàn hệ thống (Broadcast Notification) */
export const SYSTEM_BROADCAST_USER_ID = "00000000-0000-0000-0000-000000000000";

export type NotificationType = keyof typeof NOTIFICATION_TYPE;

export const NOTIFICATION_PRIORITY = {
  LOW: "LOW",
  NORMAL: "NORMAL",
  HIGH: "HIGH",
  CRITICAL: "CRITICAL",
} as const;

export type NotificationPriority = keyof typeof NOTIFICATION_PRIORITY;

export const NOTIFICATION_SEVERITY = {
  LOW: "LOW",
  NORMAL: "NORMAL",
  MEDIUM: "MEDIUM",
  HIGH: "HIGH",
  CRITICAL: "CRITICAL",
} as const;

export type NotificationSeverity = keyof typeof NOTIFICATION_SEVERITY;

export const SEVERITY_WEIGHT: Record<string, number> = {
  LOW: 1,
  NORMAL: 2,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

export const NOTIFICATION_CHANNEL = {
  IN_APP: "IN_APP",
  WEB: "WEB",
  EMAIL: "EMAIL",
  ZALO_BOT: "ZALO_BOT",
  WEBHOOK: "WEBHOOK",
} as const;

export const ALL_NOTIFICATION_CHANNELS = [
  NOTIFICATION_CHANNEL.IN_APP,
  NOTIFICATION_CHANNEL.WEB,
  NOTIFICATION_CHANNEL.EMAIL,
  NOTIFICATION_CHANNEL.ZALO_BOT,
  NOTIFICATION_CHANNEL.WEBHOOK,
] as const;

export type NotificationChannel = keyof typeof NOTIFICATION_CHANNEL;

/** Các kênh hiển thị trực tiếp trong hộp thư web (Inbox & Unread Count mặc định) */
export const INBOX_NOTIFICATION_CHANNELS = [
  NOTIFICATION_CHANNEL.IN_APP,
  NOTIFICATION_CHANNEL.WEB,
] as const;

export const NOTIFICATION_STATUS = {
  PENDING: "PENDING",
  SENT: "SENT",
  FAILED: "FAILED",
  READ: "READ",
} as const;

export type NotificationStatus = keyof typeof NOTIFICATION_STATUS;

export const NOTIFICATION_TEMPLATE_STATUS = {
  ACTIVE: "ACTIVE",
  INACTIVE: "INACTIVE",
} as const;

export type NotificationTemplateStatus =
  keyof typeof NOTIFICATION_TEMPLATE_STATUS;

export const NOTIFICATION_TEMPLATE_CODE = {
  PPE_VIOLATION_ALERT: "PPE_VIOLATION_ALERT",
  INCIDENT_ASSIGNED: "INCIDENT_ASSIGNED",
  INCIDENT_RESOLVED: "INCIDENT_RESOLVED",
  VERIFY_EMAIL: "VERIFY_EMAIL",
  RESET_PASSWORD: "RESET_PASSWORD",
  NEW_DEVICE_ALERT: "NEW_DEVICE_ALERT",
  WELCOME: "WELCOME",
  PASSWORD_CHANGED: "PASSWORD_CHANGED",
  ROLE_ASSIGNED: "ROLE_ASSIGNED",
  ACTIVITY_SUMMARY_DIGEST: "ACTIVITY_SUMMARY_DIGEST",
  CUSTOM: "CUSTOM",
} as const;

export type NotificationTemplateCode =
  keyof typeof NOTIFICATION_TEMPLATE_CODE;

export const EMAIL_TEMPLATE_KEY = {
  PPE_VIOLATION_ALERT: "PPE_VIOLATION_ALERT",
  INCIDENT_ASSIGNED: "INCIDENT_ASSIGNED",
  INCIDENT_RESOLVED: "INCIDENT_RESOLVED",
  VERIFY_EMAIL: "VERIFY_EMAIL",
  RESET_PASSWORD: "RESET_PASSWORD",
  NEW_DEVICE_ALERT: "NEW_DEVICE_ALERT",
  ACTIVITY_SUMMARY_DIGEST: "ACTIVITY_SUMMARY_DIGEST",
  CUSTOM: "CUSTOM",
} as const;

export type EmailTemplateKey = keyof typeof EMAIL_TEMPLATE_KEY;

export const EMAIL_STATUS = {
  PENDING: "PENDING",
  PROCESSING: "PROCESSING",
  SENT: "SENT",
  FAILED: "FAILED",
} as const;

export type EmailStatus = keyof typeof EMAIL_STATUS;

export const EMAIL_MAX_ATTEMPTS = 3;

export const DEFAULT_EMAIL_SUBJECTS: Record<string, string> = {
  PPE_VIOLATION_ALERT: "🚨 CẢNH BÁO VI PHẠM TRANG BỊ BẢO HỘ PPE",
  INCIDENT_ASSIGNED: "📋 BẠN ĐƯỢC PHÂN CÔNG XỬ LÝ SỰ CỐ AN TOÀN",
  INCIDENT_RESOLVED: "✅ SỰ CỐ AN TOÀN LAO ĐỘNG ĐÃ ĐƯỢC GIẢI QUYẾT",
  VERIFY_EMAIL: "Xác thực tài khoản của bạn",
  RESET_PASSWORD: "Đặt lại mật khẩu",
  NEW_DEVICE_ALERT: "Phát hiện đăng nhập từ thiết bị mới",
  ACTIVITY_SUMMARY_DIGEST: "Báo cáo tổng kết hoạt động hệ thống",
  CUSTOM: "Thông báo từ hệ thống",
};

/** Các kênh thông báo cá nhân có triển khai thực tế và hỗ trợ cấu hình tại /preferences */
export const SUPPORTED_PREFERENCE_CHANNELS = [
  NOTIFICATION_CHANNEL.IN_APP,
  NOTIFICATION_CHANNEL.EMAIL,
  NOTIFICATION_CHANNEL.ZALO_BOT,
] as const;

export type SupportedPreferenceChannel =
  (typeof SUPPORTED_PREFERENCE_CHANNELS)[number];

export const DEFAULT_PREFERENCES = [
  {
    channel: NOTIFICATION_CHANNEL.IN_APP,
    enabled: true,
    severityThreshold: NOTIFICATION_SEVERITY.LOW,
  },
  {
    channel: NOTIFICATION_CHANNEL.EMAIL,
    enabled: true,
    severityThreshold: NOTIFICATION_SEVERITY.HIGH,
  },
  {
    channel: NOTIFICATION_CHANNEL.ZALO_BOT,
    enabled: false,
    severityThreshold: NOTIFICATION_SEVERITY.HIGH,
  },
] as const;

export const ZALO_CHAT_TYPE = {
  PRIVATE: "PRIVATE",
  GROUP: "GROUP",
} as const;

export type ZaloChatType = keyof typeof ZALO_CHAT_TYPE;

export const ZALO_BOT_MODE = {
  DISABLED: "disabled",
  POLLING: "polling",
  WEBHOOK: "webhook",
} as const;

export type ZaloBotMode = (typeof ZALO_BOT_MODE)[keyof typeof ZALO_BOT_MODE];

export const ZALO_BOT_EVENT = {
  MESSAGE_TEXT: "message.text.received",
  MESSAGE_IMAGE: "message.image.received",
  MESSAGE_STICKER: "message.sticker.received",
  MESSAGE_VOICE: "message.voice.received",
  MESSAGE_UNSUPPORTED: "message.unsupported.received",
} as const;

export type ZaloBotEvent = (typeof ZALO_BOT_EVENT)[keyof typeof ZALO_BOT_EVENT];

export const ZALO_LINK_TOKEN_TTL_MS = 10 * 60 * 1000;
export const ZALO_MAX_TEXT_LENGTH = 2000;
export const ZALO_WEBHOOK_SECRET_HEADER = "x-bot-api-secret-token";

