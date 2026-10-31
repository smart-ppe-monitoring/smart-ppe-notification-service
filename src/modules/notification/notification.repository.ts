import { Prisma as NotificationPrisma } from "@prisma/client-notification";
import {
  notificationPrisma,
  DEFAULT_NOTIFICATION_TRANSACTION_OPTIONS,
} from "../../database/notification.client";
import {
  NOTIFICATION_TYPE,
  NOTIFICATION_STATUS,
  NOTIFICATION_SEVERITY,
  NOTIFICATION_CHANNEL,
  NOTIFICATION_TEMPLATE_STATUS,
  EMAIL_STATUS,
  EMAIL_MAX_ATTEMPTS,
  SYSTEM_BROADCAST_USER_ID,
} from "../../common/constants/notification.constant";
import {
  calculatePaginationSkip,
  formatPaginationMeta,
} from "../../common/helpers/pagination.helper";
import { isUuid } from "../../common/helpers/uuid.helper";
import {
  ListNotificationsDto,
  ListEmailsDto,
  ListNotificationTemplatesDto,
  CreateNotificationTemplateDto,
  UpdateNotificationTemplateDto,
  NotificationItemDto,
} from "./notification.dto";

export interface ClaimedEmailRecord {
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

export class NotificationRepository {
  private readonly db = notificationPrisma;

  // ─────────────────────────────────────────────
  // User Notifications Inbox (ppe_notification_db)
  // ─────────────────────────────────────────────

  async findMany(userId: string, dto: ListNotificationsDto) {
    const { isRead, status, severity, channel, incidentId, fromDate, toDate } = dto;
    const { skip, take, page, limit } = calculatePaginationSkip(dto.page, dto.limit);

    const where: NotificationPrisma.NotificationWhereInput = {
      OR: [
        { userId },
        { userId: SYSTEM_BROADCAST_USER_ID },
      ],
    };

    if (isRead !== undefined) {
      if (isRead) {
        where.status = NOTIFICATION_STATUS.READ;
      } else {
        where.status = { not: NOTIFICATION_STATUS.READ };
      }
    }

    if (status) {
      where.status = status;
    }

    if (severity) {
      where.severity = severity;
    }

    if (channel) {
      where.channel = channel;
    }

    if (incidentId) {
      where.incidentId = incidentId;
    }

    if (fromDate || toDate) {
      where.createdAt = {};
      if (fromDate) {
        where.createdAt.gte = new Date(fromDate);
      }
      if (toDate) {
        where.createdAt.lte = new Date(toDate);
      }
    }

    const [items, total] = await Promise.all([
      this.db.notification.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip,
        take,
        include: {
          template: {
            select: { id: true, code: true, name: true },
          },
        },
      }),
      this.db.notification.count({ where }),
    ]);

    const formattedItems: NotificationItemDto[] = items.map((item) => ({
      id: item.id,
      userId: item.userId,
      incidentId: item.incidentId,
      templateId: item.templateId,
      channel: item.channel,
      title: item.title,
      content: item.content,
      severity: item.severity,
      status: item.status,
      sentAt: item.sentAt,
      readAt: item.readAt,
      createdAt: item.createdAt,
      isRead: item.status === NOTIFICATION_STATUS.READ || Boolean(item.readAt),
      priority: item.severity,
      type:
        item.severity === NOTIFICATION_SEVERITY.CRITICAL
          ? NOTIFICATION_TYPE.ALERT
          : NOTIFICATION_TYPE.INFO,
    }));

    return [formattedItems, total, formatPaginationMeta(page, limit, total)] as const;
  }

  async countUnread(userId: string): Promise<number> {
    return this.db.notification.count({
      where: {
        userId,
        status: { not: NOTIFICATION_STATUS.READ },
      },
    });
  }

  async findOne(id: string, userId?: string) {
    const where: NotificationPrisma.NotificationWhereInput = { id };
    if (userId) {
      where.userId = userId;
    }
    return this.db.notification.findFirst({
      where,
      include: {
        template: true,
        logs: {
          orderBy: { createdAt: "desc" },
          take: 5,
        },
      },
    });
  }

  async markAsRead(id: string, userId: string) {
    return this.db.notification.updateMany({
      where: {
        id,
        userId,
        status: { not: NOTIFICATION_STATUS.READ },
      },
      data: {
        status: NOTIFICATION_STATUS.READ,
        readAt: new Date(),
      },
    });
  }

  async markAllAsRead(userId: string) {
    return this.db.notification.updateMany({
      where: {
        userId,
        status: { not: NOTIFICATION_STATUS.READ },
      },
      data: {
        status: NOTIFICATION_STATUS.READ,
        readAt: new Date(),
      },
    });
  }

  async delete(id: string, userId: string) {
    return this.db.notification.deleteMany({
      where: { id, userId },
    });
  }

  async createSingleNotification(data: {
    userId: string;
    incidentId?: string | null;
    templateId?: string | null;
    channel?: string;
    title: string;
    content: string;
    severity?: string;
    status?: string;
    sentAt?: Date | null;
  }) {
    if (!data.userId || !isUuid(data.userId)) {
      return null;
    }

    return this.db.notification.create({
      data: {
        userId: data.userId,
        incidentId: data.incidentId || null,
        templateId: data.templateId || null,
        channel: data.channel || NOTIFICATION_CHANNEL.IN_APP,
        title: data.title,
        content: data.content,
        severity: data.severity || NOTIFICATION_SEVERITY.NORMAL,
        status: data.status || NOTIFICATION_STATUS.SENT,
        sentAt: data.sentAt || new Date(),
      },
    });
  }

  async createManyNotifications(
    dataList: Array<{
      userId: string;
      incidentId?: string | null;
      templateId?: string | null;
      channel: string;
      title: string;
      content: string;
      severity?: string;
      status?: string;
      sentAt?: Date | null;
    }>,
  ) {
    const validData = dataList
      .filter((d) => d.userId && isUuid(d.userId))
      .map((d) => ({
        userId: d.userId,
        incidentId: d.incidentId || null,
        templateId: d.templateId || null,
        channel: d.channel || NOTIFICATION_CHANNEL.IN_APP,
        title: d.title,
        content: d.content,
        severity: d.severity || NOTIFICATION_SEVERITY.NORMAL,
        status: d.status || NOTIFICATION_STATUS.SENT,
        sentAt: d.sentAt || new Date(),
      }));

    if (validData.length === 0) return { count: 0 };

    return this.db.notification.createMany({
      data: validData,
    });
  }

  /**
   * Truy vấn danh sách các User ID duy nhất đã từng có tương tác trong hệ thống
   * phục vụ lưu trữ thông báo phát thanh (Broadcast Persistence - SEC-15).
   */
  async findDistinctUserIds(): Promise<string[]> {
    const [prefs, notifs] = await Promise.all([
      this.db.notificationPreference.findMany({
        select: { userId: true },
        distinct: ["userId"],
      }),
      this.db.notification.findMany({
        select: { userId: true },
        distinct: ["userId"],
        take: 1000,
      }),
    ]);
    const userSet = new Set<string>();
    prefs.forEach((p) => {
      if (p.userId && isUuid(p.userId) && p.userId !== SYSTEM_BROADCAST_USER_ID) {
        userSet.add(p.userId);
      }
    });
    notifs.forEach((n) => {
      if (n.userId && isUuid(n.userId) && n.userId !== SYSTEM_BROADCAST_USER_ID) {
        userSet.add(n.userId);
      }
    });
    return Array.from(userSet);
  }

  // ─────────────────────────────────────────────
  // User Notification Preferences
  // ─────────────────────────────────────────────

  async findUserPreferences(userId: string) {
    return this.db.notificationPreference.findMany({
      where: { userId },
    });
  }

  async findPreferencesByUserIds(userIds: string[]) {
    if (userIds.length === 0) return [];
    return this.db.notificationPreference.findMany({
      where: { userId: { in: userIds } },
    });
  }

  async findUserPreferenceForChannel(userId: string, channel: string) {
    return this.db.notificationPreference.findUnique({
      where: {
        userId_channel: {
          userId,
          channel,
        },
      },
    });
  }

  async upsertPreference(
    userId: string,
    channel: string,
    enabled: boolean,
    severityThreshold: string = NOTIFICATION_SEVERITY.LOW,
  ) {
    return this.db.notificationPreference.upsert({
      where: {
        userId_channel: {
          userId,
          channel,
        },
      },
      create: {
        userId,
        channel,
        enabled,
        severityThreshold,
      },
      update: {
        enabled,
        severityThreshold,
      },
    });
  }

  // ─────────────────────────────────────────────
  // Notification Templates (ppe_notification_db)
  // ─────────────────────────────────────────────

  async findTemplateByCode(code: string) {
    return this.db.notificationTemplate.findUnique({
      where: { code },
    });
  }

  async findTemplateById(id: string) {
    return this.db.notificationTemplate.findUnique({
      where: { id },
    });
  }

  async findTemplates(dto: ListNotificationTemplatesDto) {
    const { skip, take, page, limit } = calculatePaginationSkip(dto.page, dto.limit);
    const where: NotificationPrisma.NotificationTemplateWhereInput = {};

    if (dto.channel) {
      where.channel = dto.channel;
    }
    if (dto.status) {
      where.status = dto.status;
    }
    if (dto.search) {
      where.OR = [
        { code: { contains: dto.search, mode: "insensitive" } },
        { name: { contains: dto.search, mode: "insensitive" } },
      ];
    }

    const [items, total] = await Promise.all([
      this.db.notificationTemplate.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip,
        take,
      }),
      this.db.notificationTemplate.count({ where }),
    ]);

    return {
      data: items,
      meta: formatPaginationMeta(page, limit, total),
    };
  }

  async createTemplate(data: CreateNotificationTemplateDto) {
    return this.db.notificationTemplate.create({
      data: {
        code: data.code,
        name: data.name,
        channel: data.channel || (data.channels?.[0] as string) || NOTIFICATION_CHANNEL.IN_APP,
        subjectTemplate: data.subjectTemplate || data.subject || null,
        contentTemplate: data.contentTemplate || data.content || "",
        status:
          data.status ||
          (data.isActive === false
            ? NOTIFICATION_TEMPLATE_STATUS.INACTIVE
            : NOTIFICATION_TEMPLATE_STATUS.ACTIVE),
      },
    });
  }

  async updateTemplate(id: string, data: UpdateNotificationTemplateDto) {
    return this.db.notificationTemplate.update({
      where: { id },
      data: {
        ...(data.name && { name: data.name }),
        ...(data.channel && { channel: data.channel }),
        ...(data.subjectTemplate !== undefined && {
          subjectTemplate: data.subjectTemplate,
        }),
        ...(data.contentTemplate && { contentTemplate: data.contentTemplate }),
        ...(data.status && { status: data.status }),
      },
    });
  }

  async deleteTemplate(id: string) {
    return this.db.notificationTemplate.delete({
      where: { id },
    });
  }

  // ─────────────────────────────────────────────
  // Notification Logs
  // ─────────────────────────────────────────────

  async logNotificationAttempt(
    notificationId: string,
    status: string,
    attempt: number = 1,
    errorMessage?: string | null,
  ) {
    return this.db.notificationLog.create({
      data: {
        notificationId,
        status,
        attempt,
        errorMessage: errorMessage || null,
        sentAt: status === NOTIFICATION_STATUS.SENT ? new Date() : null,
      },
    });
  }

  // ─────────────────────────────────────────────
  // Email Worker Support (notificationPrisma)
  // ─────────────────────────────────────────────

  async claimPendingEmails(batchSize = 20): Promise<ClaimedEmailRecord[]> {
    return notificationPrisma.$queryRaw<ClaimedEmailRecord[]>`
      UPDATE email_notifications
      SET status = ${EMAIL_STATUS.PROCESSING}, updated_at = NOW()
      WHERE id IN (
        SELECT id FROM email_notifications
        WHERE (
          (
            status = ${EMAIL_STATUS.PENDING}
            AND (
              attempts = 0
              OR updated_at <= NOW() - (
                CASE
                  WHEN attempts = 1 THEN INTERVAL '30 seconds'
                  WHEN attempts = 2 THEN INTERVAL '120 seconds'
                  ELSE INTERVAL '300 seconds'
                END
              )
            )
          )
          OR (status = ${EMAIL_STATUS.PROCESSING} AND updated_at < NOW() - INTERVAL '15 minutes')
        )
        AND attempts < ${EMAIL_MAX_ATTEMPTS}
        ORDER BY created_at ASC
        LIMIT ${batchSize}
        FOR UPDATE SKIP LOCKED
      )
      RETURNING
        id,
        user_id AS "userId",
        to_email AS "toEmail",
        subject,
        template_key AS "templateKey",
        template_data AS "templateData",
        status,
        attempts,
        last_error AS "lastError",
        sent_at AS "sentAt",
        created_at AS "createdAt",
        updated_at AS "updatedAt"
    `;
  }

  async updateEmailStatus(
    id: string,
    data: {
      status: string;
      attempts?: number;
      lastError?: string | null;
      sentAt?: Date | null;
    },
  ) {
    return (notificationPrisma as any).emailNotification.update({
      where: { id },
      data: {
        status: data.status,
        ...(data.attempts !== undefined && { attempts: data.attempts }),
        ...(data.lastError !== undefined && { lastError: data.lastError }),
        ...(data.sentAt !== undefined && { sentAt: data.sentAt }),
      },
    });
  }

  async findEmailById(id: string) {
    return (notificationPrisma as any).emailNotification.findUnique({
      where: { id },
    });
  }

  async findEmails(dto: ListEmailsDto) {
    const { skip, take, page, limit } = calculatePaginationSkip(dto.page, dto.limit);
    const where: any = {};
    if (dto.status) where.status = dto.status;
    if (dto.toEmail) where.toEmail = { contains: dto.toEmail, mode: "insensitive" };
    if (dto.userId) where.userId = dto.userId;

    const [items, total] = await Promise.all([
      (notificationPrisma as any).emailNotification.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip,
        take,
      }),
      (notificationPrisma as any).emailNotification.count({ where }),
    ]);

    return {
      data: items as ClaimedEmailRecord[],
      meta: formatPaginationMeta(page, limit, total),
    };
  }

  async resetEmailForRetry(id: string) {
    return (notificationPrisma as any).emailNotification.update({
      where: { id },
      data: {
        status: EMAIL_STATUS.PENDING,
        attempts: 0,
        lastError: null,
      },
    });
  }

  async createAuditLog(params: {
    actorId?: string;
    action: string;
    targetType: string;
    targetId?: string;
    details?: Record<string, unknown>;
    ipAddress?: string;
    userAgent?: string;
  }) {
    if (!params.actorId || !isUuid(params.actorId)) return null;
    console.log(`[AuditLog] ${params.action} on ${params.targetType}:${params.targetId}`);
    return null;
  }
}

export const notificationRepository = new NotificationRepository();
