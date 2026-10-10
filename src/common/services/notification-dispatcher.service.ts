import {
  NOTIFICATION_CHANNEL,
  NotificationChannel,
  EMAIL_STATUS,
  EmailTemplateKey,
  NOTIFICATION_TYPE,
  NOTIFICATION_PRIORITY,
  NOTIFICATION_SEVERITY,
  NOTIFICATION_TEMPLATE_STATUS,
  DEFAULT_EMAIL_SUBJECTS,
} from "../constants/notification.constant";
import { renderTemplateString } from "../helpers/template.helper";
import { notificationRepository } from "../../modules/notification/notification.repository";
import { AppError } from "../errors/app-error";
import { ERROR_CODE } from "../errors/error-code";

export interface WebNotificationPayload {
  type: string;
  priority?: string;
  title: string;
  content: string;
  actionUrl?: string;
  metadata?: Record<string, unknown>;
}

export interface EmailNotificationPayload {
  toEmail: string;
  templateKey: EmailTemplateKey | string;
  templateData: Record<string, unknown>;
  subject?: string;
}

export interface NotificationEvent {
  userId: string;
  channels: NotificationChannel[];
  web?: WebNotificationPayload;
  email?: EmailNotificationPayload;
}

export interface SendWithTemplateOptions {
  userId: string;
  templateCode: string;
  variables: Record<string, unknown>;
  channels?: NotificationChannel[];
  toEmail?: string;
  actionUrl?: string;
  priority?: string;
  type?: string;
  metadata?: Record<string, unknown>;
}

class NotificationDispatcher {
  async send(event: NotificationEvent): Promise<void> {
    const tasks: Promise<unknown>[] = [];

    if (event.channels.includes(NOTIFICATION_CHANNEL.WEB)) {
      if (!event.web)
        throw new AppError(
          "web payload is required for WEB channel",
          400,
          ERROR_CODE.VALIDATION_ERROR,
        );
      tasks.push(this.dispatchWeb(event.userId, event.web));
    }

    if (event.channels.includes(NOTIFICATION_CHANNEL.EMAIL)) {
      if (!event.email)
        throw new AppError(
          "email payload is required for EMAIL channel",
          400,
          ERROR_CODE.VALIDATION_ERROR,
        );
      tasks.push(this.dispatchEmail(event.userId, event.email));
    }

    await Promise.all(tasks);
  }

  /**
   * Phân phối thông báo sử dụng mẫu Database-driven Template (NotificationTemplate).
   * Tự động thay thế các biến {{variableName}} vào title/content cho WEB và subject/content cho EMAIL.
   */
  async sendWithTemplate(options: SendWithTemplateOptions): Promise<void> {
    const { userId, templateCode, variables, toEmail, actionUrl, metadata } =
      options;

    const template =
      await notificationRepository.findTemplateByCode(templateCode);

    if (!template || template.status !== NOTIFICATION_TEMPLATE_STATUS.ACTIVE) {
      console.warn(
        `[NotificationDispatcher] Template '${templateCode}' not found or inactive.`,
      );
      return;
    }

    const targetChannels =
      options.channels || [template.channel as NotificationChannel];

    const tasks: Promise<unknown>[] = [];

    if (targetChannels.includes(NOTIFICATION_CHANNEL.WEB) || targetChannels.includes(NOTIFICATION_CHANNEL.IN_APP)) {
      const title = renderTemplateString(
        template.subjectTemplate || template.name,
        variables,
      );
      const content = renderTemplateString(template.contentTemplate, variables);
      tasks.push(
        this.dispatchWeb(userId, {
          type: options.type || NOTIFICATION_TYPE.INFO,
          priority: options.priority || NOTIFICATION_PRIORITY.NORMAL,
          title,
          content,
          actionUrl,
          metadata,
        }),
      );
    }

    if (targetChannels.includes(NOTIFICATION_CHANNEL.EMAIL)) {
      let emailAddress = toEmail;
      if (!emailAddress) {
        const user = (notificationRepository as any)?.findUserEmailById
          ? await (notificationRepository as any).findUserEmailById(userId)
          : undefined;
        emailAddress = user?.email || undefined;
      }

      if (emailAddress) {
        const subject = renderTemplateString(
          template.subjectTemplate || template.name,
          variables,
        );
        tasks.push(
          this.dispatchEmail(userId, {
            toEmail: emailAddress,
            templateKey: template.code,
            templateData: variables,
            subject,
          }),
        );
      }
    }

    await Promise.all(tasks);
  }

  private async dispatchWeb(
    userId: string,
    payload: WebNotificationPayload,
  ): Promise<void> {
    await notificationRepository.createSingleNotification({
      userId,
      channel: NOTIFICATION_CHANNEL.IN_APP,
      severity: payload.priority || NOTIFICATION_SEVERITY.NORMAL,
      title: payload.title,
      content: payload.content,
    });
  }

  private async dispatchEmail(
    userId: string,
    payload: EmailNotificationPayload,
  ): Promise<void> {
    const subject =
      payload.subject ||
      (payload.templateData["subject"] as string) ||
      DEFAULT_EMAIL_SUBJECTS[payload.templateKey] ||
      "Thông báo từ hệ thống";

    await notificationRepository.createSingleNotification({
      userId,
      channel: NOTIFICATION_CHANNEL.EMAIL,
      severity: NOTIFICATION_SEVERITY.NORMAL,
      title: subject,
      content: JSON.stringify(payload.templateData),
    });
  }

  /**
   * Tạo Web Notification nhanh — shorthand không cần EMAIL channel.
   */
  async notify(
    userId: string,
    type: string,
    title: string,
    content: string,
    options?: {
      priority?: string;
      actionUrl?: string;
      metadata?: Record<string, unknown>;
    },
  ): Promise<void> {
    await this.dispatchWeb(userId, { type, title, content, ...options });
  }
}

export const notificationDispatcher = new NotificationDispatcher();
