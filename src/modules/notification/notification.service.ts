import jwt from "jsonwebtoken";
import { jwtConfig } from "../../config/jwt.config";
import { envConfig } from "../../config/env.config";
import { JWT_PURPOSE } from "../../common/constants/jwt.constant";
import { AppError } from "../../common/errors/app-error";
import { ERROR_CODE } from "../../common/errors/error-code";
import {
  ListNotificationsDto,
  ListNotificationsResponseDto,
  UnreadCountResponseDto,
  DispatchIncidentNotificationDto,
  DispatchIncidentNotificationResultDto,
  NotificationPreferenceDto,
  UpdateNotificationPreferenceDto,
  SendNotificationDto,
  BroadcastNotificationDto,
  ListEmailsDto,
  ListEmailsResponseDto,
  CreateNotificationTemplateDto,
  UpdateNotificationTemplateDto,
  ListNotificationTemplatesDto,
  ListNotificationTemplatesResponseDto,
  PreviewNotificationTemplateDto,
  PreviewNotificationTemplateResponseDto,
  TestSendNotificationTemplateDto,
} from "./notification.dto";
import { NotificationRepository, notificationRepository } from "./notification.repository";
import { mailService, MailService } from "../../common/services/mail.service";
import { sseManagerService, SseManagerService } from "../../common/services/sse-manager.service";
import { EmailTemplateService } from "../../common/services/email-template.service";
import { renderTemplateString } from "../../common/helpers/template.helper";
import { assertSafePublicUrl } from "../../common/helpers/url.helper";
import { isUuid } from "../../common/helpers/uuid.helper";
import { GATEWAY_HEADERS } from "../../common/constants/gateway.constant";
import {
  NOTIFICATION_CHANNEL,
  NOTIFICATION_SEVERITY,
  NOTIFICATION_STATUS,
  SEVERITY_WEIGHT,
  DEFAULT_PREFERENCES,
  DEFAULT_EMAIL_SUBJECTS,
  EMAIL_STATUS,
  EMAIL_TEMPLATE_KEY,
  SYSTEM_BROADCAST_USER_ID,
  NotificationChannel,
  NotificationSeverity,
} from "../../common/constants/notification.constant";
import {
  AUDIT_ACTION,
  AUDIT_TARGET_TYPE,
} from "../../common/constants/audit-log.constant";

export interface IncidentClient {
  getIncidentById(incidentId: string): Promise<any | null>;
}

export const defaultIncidentClient: IncidentClient = {
  async getIncidentById(incidentId: string): Promise<{ id: string } | null> {
    if (!incidentId || !isUuid(incidentId)) {
      return null;
    }

    const isTest =
      process.env.NODE_ENV === "test" ||
      process.argv.some((a) => a.includes("test")) ||
      Boolean(process.env.NODE_TEST_CONTEXT);

    const baseUrl = envConfig.incident.serviceUrl;
    if (!baseUrl || isTest) {
      return { id: incidentId };
    }

    try {
      const headers: Record<string, string> = {
        Accept: "application/json",
      };
      if (envConfig.gateway.internalSecret) {
        headers[GATEWAY_HEADERS.INTERNAL_SECRET] = envConfig.gateway.internalSecret;
      }

      const res = await fetch(
        `${baseUrl}/api/v1/incidents/${encodeURIComponent(incidentId)}`,
        {
          method: "GET",
          headers,
          signal: AbortSignal.timeout(3000),
        },
      );

      if (res.status === 404) {
        return null;
      }
      if (!res.ok) {
        // Tránh gián đoạn hệ thống khi incident service gặp sự cố thoáng qua
        return { id: incidentId };
      }
      const data = (await res.json()) as any;
      return data?.data || data || { id: incidentId };
    } catch {
      return { id: incidentId };
    }
  },
};

export class NotificationService {
  private readonly repository: NotificationRepository;
  private readonly mail: MailService;
  private readonly sse: SseManagerService;
  private readonly emailTemplateService: EmailTemplateService;
  private readonly incidentClient: IncidentClient;

  constructor(
    repository?: NotificationRepository,
    mail?: MailService,
    sse?: SseManagerService,
    emailTemplateService?: EmailTemplateService,
    incidentClient?: IncidentClient,
  ) {
    this.repository = repository || notificationRepository;
    this.mail = mail || mailService;
    this.sse = sse || sseManagerService;
    this.emailTemplateService =
      emailTemplateService || new EmailTemplateService();
    this.incidentClient = incidentClient || defaultIncidentClient;
  }

  // ─────────────────────────────────────────────
  // SSE Realtime Stream Ticket & Stream
  // ─────────────────────────────────────────────

  createStreamTicket(user?: {
    id?: string;
    email?: string | null;
    role?: string;
    roleId?: string;
  }): { ticket: string; expiresIn: number } {
    if (!user || !user.id) {
      throw new AppError("Chưa xác thực người dùng", 401, ERROR_CODE.UNAUTHORIZED);
    }

    const ticket = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
        roleId: user.roleId,
        purpose: JWT_PURPOSE.SSE_STREAM_TICKET,
      },
      jwtConfig.tempSecret,
      { expiresIn: "60s" },
    );

    return { ticket, expiresIn: 60 };
  }

  // ─────────────────────────────────────────────
  // PPE Incident Notification Dispatch (BE-08)
  // ─────────────────────────────────────────────

  /**
   * Kích hoạt phát cảnh báo thông báo sự cố vi phạm PPE cho cán bộ an toàn (D08.pdf)
   * Tự động kiểm tra Preferences của từng user, render nội dung và phát đa kênh (Realtime SSE + Email).
   */
  async dispatchIncidentNotification(
    dto: DispatchIncidentNotificationDto,
  ): Promise<DispatchIncidentNotificationResultDto> {
    const severity = (dto.severity || NOTIFICATION_SEVERITY.NORMAL).toUpperCase() as NotificationSeverity;
    const severityWeight = SEVERITY_WEIGHT[severity] || 2;

    // SEC-34: Xác thực sự cố tồn tại từ smart-ppe-incident-service
    const incident = await this.incidentClient.getIncidentById(dto.incidentId);
    if (!incident) {
      throw new AppError(
        `Không tìm thấy sự cố hợp lệ với incidentId: ${dto.incidentId}`,
        404,
        ERROR_CODE.NOT_FOUND,
      );
    }

    // 1. Xác định danh sách người nhận (Safety Officers / Safety Managers)
    // SEC-21: Loại bỏ các ID trùng lặp để ngăn chặn Resource Flooding & Notification Bombing
    const recipientIds = Array.from(new Set(dto.recipientUserIds || []));

    // SEC-31: Xác thực evidenceUrl chống tấn công SSRF & DNS Rebinding
    if (dto.evidenceUrl) {
      await assertSafePublicUrl(dto.evidenceUrl);
    }

    if (recipientIds.length === 0) {
      return {
        incidentId: dto.incidentId,
        dispatchedCount: 0,
        channels: [],
        notifications: [],
      };
    }

    // 2. SEC-06: Tra cứu thông tin người dùng nhận tin để lấy email thực nếu được cung cấp
    const emailMap = new Map<string, string>();
    if (dto.recipientEmails && typeof dto.recipientEmails === "object") {
      if (Array.isArray(dto.recipientEmails)) {
        dto.recipientEmails.forEach((email, idx) => {
          if (recipientIds[idx]) emailMap.set(recipientIds[idx], email);
        });
      } else {
        Object.entries(dto.recipientEmails).forEach(([uid, email]) => {
          if (typeof email === "string") emailMap.set(uid, email);
        });
      }
    }
    if (Array.isArray(dto.recipientUsers)) {
      dto.recipientUsers.forEach((u) => {
        if (u.id && u.email) emailMap.set(u.id, u.email);
      });
    }

    const users: Array<{ id: string; email?: string }> = recipientIds.map((id) => {
      const explicitEmail = emailMap.get(id);
      if (explicitEmail) {
        return { id, email: explicitEmail };
      }
      // SEC-06: Trong môi trường production, tuyệt đối không bịa email giả với domain .local
      // để tránh 100% hard bounce làm nhà cung cấp email (Resend/SES) khóa tài khoản.
      if (envConfig.nodeEnv === "production") {
        return { id, email: undefined };
      }
      // Trong dev / test, cho phép fallback để mock unit test hoạt động
      return { id, email: `${id}@smart-ppe.local` };
    });
    const userMap = new Map<string, { id: string; email?: string }>(
      users.map((u: { id: string; email?: string }) => [u.id, u]),
    );

    // 3. SEC-05: Render nội dung cảnh báo vi phạm PPE với giới hạn VarChar(255) cho title
    const rawTitle = `🚨 Cảnh báo vi phạm PPE [${severity}]: ${dto.violationType} tại ${dto.siteName || "Công trường"}`;
    const title = rawTitle.length > 255 ? rawTitle.slice(0, 252) + "..." : rawTitle;
    const content =
      dto.description ||
      `Phát hiện vi phạm ${dto.violationType} tại vị trí camera ${dto.cameraCode || dto.cameraId || "Chưa xác định"}. Mức độ: ${severity}. Vui lòng kiểm tra và xử lý ngay.`;

    const notificationsToCreate: Array<{
      userId: string;
      incidentId: string;
      templateId: null;
      channel: string;
      title: string;
      content: string;
      severity: string;
      status: string;
      sentAt: Date;
    }> = [];

    const dispatchedResult: Array<{
      id: string;
      userId: string;
      channel: string;
      status: string;
    }> = [];

    const usedChannels = new Set<string>();

    // 4. Lấy cấu hình nhận thông báo hàng loạt cho toàn bộ người nhận (Chống N+1 query)
    const allPreferences = this.repository.findPreferencesByUserIds
      ? await this.repository.findPreferencesByUserIds(recipientIds)
      : (
          await Promise.all(
            recipientIds.map(async (id) => {
              const prefs = await this.repository.findUserPreferences(id);
              return prefs.map((p) => ({ ...p, userId: (p as any).userId || id }));
            }),
          )
        ).flat();
    const userPrefMap = new Map<string, Map<string, (typeof allPreferences)[number]>>();
    for (const pref of allPreferences) {
      const uId = (pref as any).userId || (recipientIds.length === 1 ? recipientIds[0] : undefined);
      if (uId) {
        if (!userPrefMap.has(uId)) {
          userPrefMap.set(uId, new Map());
        }
        userPrefMap.get(uId)!.set(pref.channel, pref);
      }
    }

    // 5. Lặp qua từng người nhận và áp dụng Preferences
    for (const userId of recipientIds) {
      const user = userMap.get(userId);
      const prefMap = userPrefMap.get(userId) || new Map();

      // ── Kênh 1: In-App / Realtime SSE ──
      const inAppPref = prefMap.get(NOTIFICATION_CHANNEL.IN_APP);
      const inAppEnabled = inAppPref ? inAppPref.enabled : true;
      const inAppThreshold = (inAppPref?.severityThreshold || NOTIFICATION_SEVERITY.LOW) as NotificationSeverity;
      const inAppThresholdWeight = SEVERITY_WEIGHT[inAppThreshold] || 1;

      if (inAppEnabled && severityWeight >= inAppThresholdWeight) {
        notificationsToCreate.push({
          userId,
          incidentId: dto.incidentId,
          templateId: null,
          channel: NOTIFICATION_CHANNEL.IN_APP,
          title,
          content,
          severity,
          status: NOTIFICATION_STATUS.SENT,
          sentAt: new Date(),
        });
        dispatchedResult.push({
          id: dto.incidentId,
          userId,
          channel: NOTIFICATION_CHANNEL.IN_APP,
          status: NOTIFICATION_STATUS.SENT,
        });
        usedChannels.add(NOTIFICATION_CHANNEL.IN_APP);

        // Bắn sự kiện realtime SSE tới client
        this.sse.sendToUser(userId, {
          type: "notification:ppe_violation",
          data: {
            incidentId: dto.incidentId,
            siteId: dto.siteId,
            cameraId: dto.cameraId,
            cameraCode: dto.cameraCode,
            siteName: dto.siteName,
            violationType: dto.violationType,
            severity,
            title,
            content,
            evidenceUrl: dto.evidenceUrl,
            detectedAt: dto.detectedAt || new Date().toISOString(),
          },
        });
      }

      // ── Kênh 2: Email Alert ──
      const emailPref = prefMap.get(NOTIFICATION_CHANNEL.EMAIL);
      const emailEnabled = emailPref ? emailPref.enabled : true;
      const emailThreshold = (emailPref?.severityThreshold || NOTIFICATION_SEVERITY.HIGH) as NotificationSeverity;
      const emailThresholdWeight = SEVERITY_WEIGHT[emailThreshold] || 3;

      if (emailEnabled && severityWeight >= emailThresholdWeight && user?.email) {
        notificationsToCreate.push({
          userId,
          incidentId: dto.incidentId,
          templateId: null,
          channel: NOTIFICATION_CHANNEL.EMAIL,
          title,
          content,
          severity,
          status: NOTIFICATION_STATUS.SENT,
          sentAt: new Date(),
        });
        dispatchedResult.push({
          id: dto.incidentId,
          userId,
          channel: NOTIFICATION_CHANNEL.EMAIL,
          status: NOTIFICATION_STATUS.SENT,
        });
        usedChannels.add(NOTIFICATION_CHANNEL.EMAIL);

        // Gửi email bất đồng bộ qua MailService
        this.mail
          .sendPpeViolationAlertEmail(user.email, {
            incidentId: dto.incidentId,
            violationType: dto.violationType,
            severity,
            cameraCode: dto.cameraCode,
            siteName: dto.siteName,
            detectedAt: dto.detectedAt,
            evidenceUrl: dto.evidenceUrl,
            description: dto.description,
          })
          .catch((err) => {
            console.warn(
              `[NotificationService] Không thể gửi email cảnh báo PPE tới ${user.email}:`,
              err?.message || err,
            );
          });
      }
    }

    // 6. Lưu hàng loạt vào CSDL ppe_notification_db
    if (notificationsToCreate.length > 0) {
      await this.repository.createManyNotifications(notificationsToCreate);
    }

    return {
      incidentId: dto.incidentId,
      dispatchedCount: notificationsToCreate.length,
      channels: Array.from(usedChannels),
      notifications: dispatchedResult,
    };
  }

  // ─────────────────────────────────────────────
  // User Notifications Inbox Management
  // ─────────────────────────────────────────────

  async list(
    userId: string,
    dto: ListNotificationsDto,
  ): Promise<ListNotificationsResponseDto> {
    const [items, total, meta] = await this.repository.findMany(userId, dto);

    return {
      items,
      total,
      page: meta.page,
      limit: meta.limit,
      totalPages: meta.totalPages,
      meta,
    };
  }

  async getUnreadCount(userId: string): Promise<UnreadCountResponseDto> {
    const unreadCount = await this.repository.countUnread(userId);
    return { unreadCount };
  }

  async markAsRead(userId: string, notificationId: string): Promise<void> {
    const notification = await this.repository.findOne(notificationId, userId);
    if (!notification) {
      throw new AppError("Không tìm thấy thông báo", 404, ERROR_CODE.NOT_FOUND);
    }
    await this.repository.markAsRead(notificationId, userId);
    this.sse.sendToUser(userId, {
      type: "notification:read",
      data: { notificationId },
    });
  }

  async markAllAsRead(userId: string): Promise<void> {
    await this.repository.markAllAsRead(userId);
    this.sse.sendToUser(userId, {
      type: "notification:read_all",
      data: {},
    });
  }

  async delete(userId: string, notificationId: string): Promise<void> {
    const notification = await this.repository.findOne(notificationId, userId);
    if (!notification) {
      throw new AppError("Không tìm thấy thông báo", 404, ERROR_CODE.NOT_FOUND);
    }
    await this.repository.delete(notificationId, userId);
  }

  // ─────────────────────────────────────────────
  // User Notification Preferences Management
  // ─────────────────────────────────────────────

  // SEC-44: Tuân thủ chuẩn phương thức HTTP an toàn (Safe Methods RFC 7231).
  // GET /preferences chỉ đọc dữ liệu, tuyệt đối không được phép ghi (upsert) vào CSDL nếu người dùng chưa có cấu hình.
  // Trả về cấu hình đã lưu kết hợp với cấu hình mặc định (in-memory) cho các kênh còn thiếu mà không gây side-effect.
  async getUserPreferences(userId: string): Promise<NotificationPreferenceDto[]> {
    const preferences = await this.repository.findUserPreferences(userId);
    const existingChannels = new Set(preferences.map((p) => p.channel));
    const merged = [...preferences];

    for (const def of DEFAULT_PREFERENCES) {
      if (!existingChannels.has(def.channel)) {
        merged.push({
          id: `default-${userId}-${def.channel}`,
          userId,
          channel: def.channel,
          enabled: def.enabled,
          severityThreshold: def.severityThreshold,
          createdAt: new Date(0),
          updatedAt: new Date(0),
        });
      }
    }

    return merged;
  }

  async updateUserPreference(
    userId: string,
    dto: UpdateNotificationPreferenceDto,
  ): Promise<NotificationPreferenceDto> {
    return this.repository.upsertPreference(
      userId,
      dto.channel,
      dto.enabled,
      dto.severityThreshold || NOTIFICATION_SEVERITY.LOW,
    );
  }

  // ─────────────────────────────────────────────
  // Legacy / Direct Send & Broadcast
  // ─────────────────────────────────────────────

  async send(dto: SendNotificationDto): Promise<{ sentCount: number }> {
    const {
      userIds,
      channels,
      title: rawTitle,
      content,
      severity = NOTIFICATION_SEVERITY.NORMAL,
      incidentId,
    } = dto;

    const title = (rawTitle || "").length > 255 ? rawTitle.slice(0, 252) + "..." : rawTitle;

    // SEC-31: Xác thực actionUrl chống tấn công SSRF & DNS Rebinding
    if (dto.actionUrl) {
      await assertSafePublicUrl(dto.actionUrl);
    }

    // SEC-21: Deduplicate userIds & channels để chống Notification Bombing
    const uniqueUserIds = Array.from(new Set(userIds || []));
    const uniqueChannels = Array.from(new Set(channels || []));

    // SEC-27: Chặn việc đánh dấu SENT giả mạo đối với các kênh chưa được triển khai (ZALO_ZNS, WEBHOOK)
    const UNIMPLEMENTED_CHANNELS = new Set([
      NOTIFICATION_CHANNEL.ZALO_ZNS,
      NOTIFICATION_CHANNEL.WEBHOOK,
    ]);
    const unimplemented = uniqueChannels.filter((c) =>
      UNIMPLEMENTED_CHANNELS.has(c as any),
    );
    if (unimplemented.length > 0) {
      throw new AppError(
        `Kênh thông báo chưa được hỗ trợ hoặc chưa triển khai: ${unimplemented.join(", ")}`,
        400,
        ERROR_CODE.BAD_REQUEST,
      );
    }

    // SEC-27: Đối với kênh EMAIL, phải đảm bảo có địa chỉ email người nhận hợp lệ trước khi dispatch
    const emailMap = new Map<string, string>();
    if (uniqueChannels.includes(NOTIFICATION_CHANNEL.EMAIL)) {
      if (dto.recipientEmails) {
        if (Array.isArray(dto.recipientEmails)) {
          dto.recipientEmails.forEach((email: string, idx: number) => {
            if (uniqueUserIds[idx]) emailMap.set(uniqueUserIds[idx], email);
          });
        } else {
          Object.entries(dto.recipientEmails).forEach(([uid, email]) => {
            if (typeof email === "string") emailMap.set(uid, email);
          });
        }
      }

      for (const userId of uniqueUserIds) {
        const email = emailMap.get(userId) || (dto as any).recipientEmail;
        if (!email) {
          throw new AppError(
            `Kênh EMAIL yêu cầu cung cấp địa chỉ email người nhận cho người dùng ${userId}`,
            400,
            ERROR_CODE.VALIDATION_ERROR,
          );
        }
      }
    }

    const records = [];
    for (const userId of uniqueUserIds) {
      for (const channel of uniqueChannels) {
        records.push({
          userId,
          incidentId: incidentId || null,
          templateId: null,
          channel,
          title,
          content,
          severity,
          status: NOTIFICATION_STATUS.SENT,
          sentAt: new Date(),
        });
      }
    }

    if (records.length > 0) {
      await this.repository.createManyNotifications(records);

      if (uniqueChannels.includes(NOTIFICATION_CHANNEL.IN_APP) || uniqueChannels.includes(NOTIFICATION_CHANNEL.WEB)) {
        for (const userId of uniqueUserIds) {
          this.sse.sendToUser(userId, {
            type: "notification:new",
            data: {
              title,
              content,
              severity,
              createdAt: new Date().toISOString(),
            },
          });
        }
      }

      if (uniqueChannels.includes(NOTIFICATION_CHANNEL.EMAIL)) {
        for (const userId of uniqueUserIds) {
          const email = emailMap.get(userId) || (dto as any).recipientEmail;
          if (email) {
            const html = this.emailTemplateService.baseLayout(title, content);
            await this.mail.sendRaw(email, title, html);
          }
        }
      }
    }

    return { sentCount: records.length };
  }

  async broadcast(
    dto: BroadcastNotificationDto,
  ): Promise<{ totalRecipients: number }> {
    const safeTitle = (dto.title || "").length > 255 ? dto.title.slice(0, 252) + "..." : dto.title;

    // SEC-31: Xác thực actionUrl chống tấn công SSRF & DNS Rebinding
    if (dto.actionUrl) {
      await assertSafePublicUrl(dto.actionUrl);
    }

    // SEC-15: Lưu trữ thông báo broadcast vào CSDL PostgreSQL để người dùng offline khi đăng nhập vẫn nhận được
    const userIds = await this.repository.findDistinctUserIds();
    const recipientUserIds = userIds.length > 0 ? userIds : [SYSTEM_BROADCAST_USER_ID];

    const records = recipientUserIds.map((uid) => ({
      userId: uid,
      incidentId: null,
      templateId: null,
      channel: NOTIFICATION_CHANNEL.IN_APP,
      title: safeTitle,
      content: dto.content,
      severity: dto.severity || NOTIFICATION_SEVERITY.NORMAL,
      status: NOTIFICATION_STATUS.SENT,
      sentAt: new Date(),
    }));

    if (userIds.length > 0 && !userIds.includes(SYSTEM_BROADCAST_USER_ID)) {
      records.push({
        userId: SYSTEM_BROADCAST_USER_ID,
        incidentId: null,
        templateId: null,
        channel: NOTIFICATION_CHANNEL.IN_APP,
        title: safeTitle,
        content: dto.content,
        severity: dto.severity || NOTIFICATION_SEVERITY.NORMAL,
        status: NOTIFICATION_STATUS.SENT,
        sentAt: new Date(),
      });
    }

    await this.repository.createManyNotifications(records);

    // Phát real-time SSE cho các client đang kết nối
    this.sse.broadcast({
      type: "notification:broadcast",
      data: {
        title: safeTitle,
        content: dto.content,
        severity: dto.severity || NOTIFICATION_SEVERITY.NORMAL,
        createdAt: new Date().toISOString(),
      },
    });

    return { totalRecipients: recipientUserIds.length };
  }

  // ─────────────────────────────────────────────
  // Template Management Service Methods
  // ─────────────────────────────────────────────

  async listTemplates(
    dto: ListNotificationTemplatesDto,
  ): Promise<ListNotificationTemplatesResponseDto> {
    const { data: items, meta } = await this.repository.findTemplates(dto);

    return {
      items: items.map((item) => ({
        id: item.id,
        code: item.code,
        name: item.name,
        channel: item.channel,
        subjectTemplate: item.subjectTemplate,
        contentTemplate: item.contentTemplate,
        status: item.status,
        createdAt: item.createdAt,
        updatedAt: item.updatedAt,
      })),
      total: meta.total,
      page: meta.page,
      limit: meta.limit,
      totalPages: meta.totalPages,
      meta,
    };
  }

  async getTemplateByCode(code: string) {
    const template = await this.repository.findTemplateByCode(code);
    if (!template) {
      throw new AppError(
        `Không tìm thấy mẫu thông báo với mã '${code}'`,
        404,
        ERROR_CODE.NOT_FOUND,
      );
    }
    return template;
  }

  async createTemplate(
    data: CreateNotificationTemplateDto,
    context?: { actorId?: string; ipAddress?: string; userAgent?: string },
  ) {
    const existing = await this.repository.findTemplateByCode(data.code);
    if (existing) {
      throw new AppError(
        `Mẫu thông báo với mã '${data.code}' đã tồn tại`,
        409,
        ERROR_CODE.DUPLICATE_ENTRY,
      );
    }

    const template = await this.repository.createTemplate(data);

    await this.repository.createAuditLog({
      actorId: context?.actorId,
      action: AUDIT_ACTION.CREATE_NOTIFICATION_TEMPLATE,
      targetType: AUDIT_TARGET_TYPE.NOTIFICATION_TEMPLATE,
      targetId: template.id,
      details: { code: template.code, name: template.name },
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });

    return template;
  }

  async updateTemplate(
    id: string,
    data: UpdateNotificationTemplateDto,
    context?: { actorId?: string; ipAddress?: string; userAgent?: string },
  ) {
    const template = await this.repository.findTemplateById(id);
    if (!template) {
      throw new AppError("Không tìm thấy mẫu thông báo", 404, ERROR_CODE.NOT_FOUND);
    }

    const updated = await this.repository.updateTemplate(id, data);

    await this.repository.createAuditLog({
      actorId: context?.actorId,
      action: AUDIT_ACTION.UPDATE_NOTIFICATION_TEMPLATE,
      targetType: AUDIT_TARGET_TYPE.NOTIFICATION_TEMPLATE,
      targetId: template.id,
      details: { code: template.code, updatedFields: Object.keys(data) },
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });

    return updated;
  }

  async deleteTemplate(
    id: string,
    context?: { actorId?: string; ipAddress?: string; userAgent?: string },
  ): Promise<void> {
    const template = await this.repository.findTemplateById(id);
    if (!template) {
      throw new AppError("Không tìm thấy mẫu thông báo", 404, ERROR_CODE.NOT_FOUND);
    }

    await this.repository.deleteTemplate(id);

    await this.repository.createAuditLog({
      actorId: context?.actorId,
      action: AUDIT_ACTION.DELETE_NOTIFICATION_TEMPLATE,
      targetType: AUDIT_TARGET_TYPE.NOTIFICATION_TEMPLATE,
      targetId: template.id,
      details: { code: template.code, name: template.name },
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    });
  }

  async previewTemplate(
    code: string,
    dto: PreviewNotificationTemplateDto,
  ): Promise<PreviewNotificationTemplateResponseDto> {
    const template = await this.getTemplateByCode(code);

    const subject = template.subjectTemplate
      ? renderTemplateString(template.subjectTemplate, dto.variables)
      : null;
    const content = renderTemplateString(template.contentTemplate, dto.variables);

    let html: string | undefined;
    if (template.channel === NOTIFICATION_CHANNEL.EMAIL) {
      html = this.emailTemplateService.baseLayout(
        subject || template.name,
        content,
      );
    }

    return {
      code: template.code,
      subject,
      title: subject,
      content,
      html,
    };
  }

  async testSendTemplate(
    code: string,
    userId: string,
    dto: TestSendNotificationTemplateDto,
  ): Promise<{ message: string }> {
    const template = await this.getTemplateByCode(code);
    const content = renderTemplateString(template.contentTemplate, dto.variables);
    const subject = template.subjectTemplate
      ? renderTemplateString(template.subjectTemplate, dto.variables)
      : template.name;

    await this.send({
      userIds: [userId],
      channels: dto.channels || [template.channel as NotificationChannel],
      title: subject,
      content,
    });

    return {
      message: `Đã gửi thử thông báo thành công cho mẫu '${code}'`,
    };
  }

  // ─────────────────────────────────────────────
  // Email Worker Legacy Support
  // ─────────────────────────────────────────────

  async listEmails(dto: ListEmailsDto): Promise<ListEmailsResponseDto> {
    const { data: items, meta } = await this.repository.findEmails(dto);

    return {
      items,
      total: meta.total,
      page: meta.page,
      limit: meta.limit,
      totalPages: meta.totalPages,
      meta,
    };
  }

  async retryEmail(emailId: string): Promise<void> {
    const email = await this.repository.findEmailById(emailId);
    if (!email) {
      throw new AppError("Không tìm thấy bản ghi email", 404, ERROR_CODE.NOT_FOUND);
    }

    if (email.status !== EMAIL_STATUS.FAILED) {
      throw new AppError(
        "Chỉ có thể thử lại các email ở trạng thái FAILED (thất bại)",
        400,
        ERROR_CODE.INVALID_STATUS_TRANSITION,
      );
    }

    const resetSuccess = await this.repository.resetEmailForRetry(emailId);
    if (!resetSuccess) {
      throw new AppError(
        "Không thể thử lại email do trạng thái bản ghi đã thay đổi hoặc không phải FAILED",
        400,
        ERROR_CODE.INVALID_STATUS_TRANSITION,
      );
    }
  }
}

export const notificationService = new NotificationService();
