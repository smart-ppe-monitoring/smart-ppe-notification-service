import { eventBus, EventBusService } from "../services/event-bus.service";
import { EVENT_NAMES } from "../constants/event.constant";
import { NOTIFICATION_CHANNEL } from "../constants/notification.constant";
import { FEATURE_FLAGS } from "../constants/system-config.constant";
import { MailService } from "../services/mail.service";
import {
  systemConfigCacheService,
  SystemConfigCacheService,
} from "../services/system-config-cache.service";
import {
  notificationRepository,
  NotificationRepository,
} from "../../modules/notification/notification.repository";
import { isUuid } from "../helpers/uuid.helper";
import {
  UserRegisteredPayload,
  VerificationRequestedPayload,
  PasswordResetRequestedPayload,
  NewDeviceDetectedPayload,
  DeactivationRequestedPayload,
  EventEnvelope,
} from "../types/event.type";

export class NotificationSubscriber {
  private readonly mailService: MailService;
  private readonly bus: EventBusService;
  private readonly configService: Pick<
    SystemConfigCacheService,
    "isFeatureEnabled"
  >;
  private readonly repository: Pick<
    NotificationRepository,
    "findUserPreferenceForChannel"
  >;

  constructor(
    mailService?: MailService,
    bus?: EventBusService,
    configService?: Pick<SystemConfigCacheService, "isFeatureEnabled">,
    repository?: Pick<NotificationRepository, "findUserPreferenceForChannel">,
  ) {
    this.mailService = mailService || new MailService();
    this.bus = bus || eventBus;
    this.configService = configService || systemConfigCacheService;
    this.repository = repository || notificationRepository;
  }

  public register(): void {
    // 1. Consumer: auth.user_registered
    this.bus.subscribe(
      EVENT_NAMES.AUTH_USER_REGISTERED,
      async (envelope: EventEnvelope<UserRegisteredPayload>) => {
        const { email, verifyToken, fullName } = envelope.payload;
        try {
          await this.mailService.sendVerificationEmail(
            email,
            verifyToken,
            fullName || undefined,
          );
          console.log(
            `[NotificationSubscriber] ✅ Sent verification email for user: ${envelope.payload.userId}`,
          );
        } catch (err: any) {
          console.error(
            `[NotificationSubscriber] ❌ Failed to send verification email:`,
            err?.message || err,
          );
          throw err; // Nack to trigger retry/DLQ
        }
      },
    );

    // 2. Consumer: auth.verification_requested (Resend verification email)
    this.bus.subscribe(
      EVENT_NAMES.AUTH_VERIFICATION_REQUESTED,
      async (envelope: EventEnvelope<VerificationRequestedPayload>) => {
        const { email, verifyToken, fullName } = envelope.payload;
        try {
          await this.mailService.sendVerificationEmail(
            email,
            verifyToken,
            fullName || undefined,
          );
          console.log(
            `[NotificationSubscriber] ✅ Resent verification email for user: ${envelope.payload.userId}`,
          );
        } catch (err: any) {
          console.error(
            `[NotificationSubscriber] ❌ Failed to resend verification email:`,
            err?.message || err,
          );
          throw err; // Nack to trigger retry/DLQ
        }
      },
    );

    // 3. Consumer: auth.password_reset_requested
    this.bus.subscribe(
      EVENT_NAMES.AUTH_PASSWORD_RESET_REQUESTED,
      async (envelope: EventEnvelope<PasswordResetRequestedPayload>) => {
        const { email, resetToken } = envelope.payload;
        try {
          await this.mailService.sendPasswordResetEmail(email, resetToken);
          console.log(
            `[NotificationSubscriber] ✅ Sent password reset email for user: ${envelope.payload.userId}`,
          );
        } catch (err: any) {
          console.error(
            `[NotificationSubscriber] ❌ Failed to send password reset email:`,
            err?.message || err,
          );
          throw err; // Nack to trigger retry/DLQ
        }
      },
    );

    // 4. Consumer: auth.new_device_detected
    this.bus.subscribe(
      EVENT_NAMES.AUTH_NEW_DEVICE_DETECTED,
      async (envelope: EventEnvelope<NewDeviceDetectedPayload>) => {
        const { userId, email, deviceName, ip } = envelope.payload;
        try {
          const notificationsEnabled =
            await this.configService.isFeatureEnabled(
              FEATURE_FLAGS.NOTIFICATIONS_ENABLED,
              true,
            );
          if (!notificationsEnabled) {
            return;
          }

          if (userId && isUuid(userId)) {
            const emailPref =
              await this.repository.findUserPreferenceForChannel(
                userId,
                NOTIFICATION_CHANNEL.EMAIL,
              );
            if (emailPref && emailPref.enabled === false) {
              return;
            }
          }

          await this.mailService.sendNewDeviceAlertEmail(email, {
            deviceName,
            ipAddress: ip || "Không rõ",
            loginTime: new Date(envelope.timestamp),
          });
          const maskedEmail = email.replace(/(.{2})(.*)(@.*)/, "$1***$3");
          console.log(
            `[NotificationSubscriber] ✅ Sent new device alert to ${maskedEmail}`,
          );
        } catch (err: any) {
          console.warn(
            `[NotificationSubscriber] ⚠️ Failed to send new device alert email:`,
            err?.message || err,
          );
          // Không throw để tránh retry làm phiền user nếu chỉ là cảnh báo thiết bị
        }
      },
    );

    // 5. Consumer: auth.deactivation_requested (Account deactivation request email)
    this.bus.subscribe(
      EVENT_NAMES.AUTH_DEACTIVATION_REQUESTED,
      async (envelope: EventEnvelope<DeactivationRequestedPayload>) => {
        const { email, deactivationToken, fullName } = envelope.payload;
        try {
          await this.mailService.sendAccountDeactivationEmail(
            email,
            deactivationToken,
            fullName || undefined,
          );
          console.log(
            `[NotificationSubscriber] ✅ Sent account deactivation email for user: ${envelope.payload.userId}`,
          );
        } catch (err: any) {
          console.error(
            `[NotificationSubscriber] ❌ Failed to send account deactivation email:`,
            err?.message || err,
          );
          throw err; // Nack to trigger retry/DLQ
        }
      },
    );
  }
}

export const notificationSubscriber = new NotificationSubscriber();
