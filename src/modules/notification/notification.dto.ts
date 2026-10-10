import {
  NotificationChannel,
  NotificationSeverity,
  NotificationStatus,
} from "../../common/constants/notification.constant";
import { PaginationMeta } from "../../common/types/pagination.type";

export interface ListNotificationsDto {
  page?: number;
  limit?: number;
  isRead?: boolean;
  status?: string;
  severity?: string;
  channel?: string;
  incidentId?: string;
  type?: string;
  fromDate?: string;
  toDate?: string;
}

export interface NotificationItemDto {
  id: string;
  userId: string;
  incidentId: string | null;
  templateId: string | null;
  channel: string;
  title: string;
  content: string;
  severity: string;
  status: string;
  sentAt: Date | null;
  readAt: Date | null;
  createdAt: Date;
  // Các trường bổ sung tương thích In-App UI
  isRead?: boolean;
  type?: string;
  priority?: string;
  actionUrl?: string | null;
  metadata?: unknown;
}

export interface ListNotificationsResponseDto {
  items: NotificationItemDto[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
  meta?: PaginationMeta;
}

export interface UnreadCountResponseDto {
  unreadCount: number;
}

// ─────────────────────────────────────────────
// PPE Incident Notification Dispatch DTOs
// ─────────────────────────────────────────────

export interface DispatchIncidentNotificationDto {
  incidentId: string;
  siteId?: string;
  cameraId?: string;
  cameraCode?: string;
  siteName?: string;
  violationType: string;
  severity: string;
  description?: string;
  evidenceUrl?: string;
  detectedAt?: Date | string;
  recipientUserIds?: string[];
  channels?: NotificationChannel[];
}

export interface DispatchIncidentNotificationResultDto {
  incidentId: string;
  dispatchedCount: number;
  channels: string[];
  notifications: Array<{
    id: string;
    userId: string;
    channel: string;
    status: string;
  }>;
}

// ─────────────────────────────────────────────
// User Notification Preferences DTOs
// ─────────────────────────────────────────────

export interface NotificationPreferenceDto {
  id: string;
  userId: string;
  channel: string;
  enabled: boolean;
  severityThreshold: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface UpdateNotificationPreferenceDto {
  channel: NotificationChannel;
  enabled: boolean;
  severityThreshold?: NotificationSeverity;
}

// ─────────────────────────────────────────────
// Notification Template DTOs
// ─────────────────────────────────────────────

export interface CreateNotificationTemplateDto {
  code: string;
  name: string;
  channel: string;
  subjectTemplate?: string | null;
  contentTemplate: string;
  status?: string;
  description?: string;
  channels?: NotificationChannel[];
  subject?: string;
  title?: string;
  content?: string;
  variables?: string[];
  isActive?: boolean;
}

export interface UpdateNotificationTemplateDto {
  name?: string;
  channel?: string;
  subjectTemplate?: string | null;
  contentTemplate?: string;
  status?: string;
  description?: string;
  channels?: NotificationChannel[];
  subject?: string;
  title?: string;
  content?: string;
  variables?: string[];
  isActive?: boolean;
}

export interface ListNotificationTemplatesDto {
  page?: number;
  limit?: number;
  channel?: string;
  status?: string;
  search?: string;
  isActive?: boolean;
}

export interface NotificationTemplateItemDto {
  id: string;
  code: string;
  name: string;
  channel: string;
  subjectTemplate: string | null;
  contentTemplate: string;
  status: string;
  createdAt: Date;
  updatedAt: Date;
  // Bổ sung tương thích template cũ
  description?: string | null;
  channels?: unknown;
  subject?: string | null;
  title?: string | null;
  content?: string;
  variables?: unknown;
  isSystem?: boolean;
  isActive?: boolean;
}

export interface ListNotificationTemplatesResponseDto {
  items: NotificationTemplateItemDto[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
  meta?: PaginationMeta;
}

export interface PreviewNotificationTemplateDto {
  variables: Record<string, unknown>;
}

export interface PreviewNotificationTemplateResponseDto {
  code: string;
  subject: string | null;
  title: string | null;
  content: string;
  html?: string;
}

export interface TestSendNotificationTemplateDto {
  toEmail?: string;
  variables: Record<string, unknown>;
  channels?: NotificationChannel[];
}

// ─────────────────────────────────────────────
// Legacy Admin / System Notification DTOs
// ─────────────────────────────────────────────

export interface SendNotificationDto {
  userIds: string[];
  channels: NotificationChannel[];
  title: string;
  content: string;
  severity?: NotificationSeverity;
  incidentId?: string;
  type?: string;
  priority?: string;
  actionUrl?: string;
  metadata?: Record<string, unknown>;
  templateKey?: string;
  templateData?: Record<string, unknown>;
}

export interface BroadcastNotificationDto {
  title: string;
  content: string;
  severity?: NotificationSeverity;
  type?: string;
  priority?: string;
  actionUrl?: string;
  metadata?: Record<string, unknown>;
}

export interface ListEmailsDto {
  page?: number;
  limit?: number;
  status?: string;
  toEmail?: string;
}

export interface EmailItemDto {
  id: string;
  userId: string | null;
  toEmail: string;
  subject: string;
  templateKey: string;
  templateData: unknown;
  status: string;
  attempts: number;
  lastError: string | null;
  sentAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ListEmailsResponseDto {
  items: EmailItemDto[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
  meta?: PaginationMeta;
}
