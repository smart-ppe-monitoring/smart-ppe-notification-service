import dns from "node:dns";
import nodemailer, { Transporter } from "nodemailer";
import { envConfig } from "../../config/env.config";
import { mailConfig } from "../../config/mail.config";
import { formatVietnamDateTime } from "../helpers/date.helper";
import { escapeHtml } from "../helpers/template.helper";
import { NOTIFICATION_SEVERITY } from "../constants/notification.constant";

// Force IPv4-first resolution in Node.js runtime to prevent ENETUNREACH on platforms without IPv6 routing (e.g. Render, Railway, Docker)
try {
  dns.setDefaultResultOrder?.("ipv4first");
} catch {}

// Prevent nodemailer from selecting IPv6 addresses when running in containers without public IPv6 routing
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const shared = require("nodemailer/lib/shared");
  if (shared) {
    if (typeof shared.networkInterfaces === "function") {
      const origNetworkInterfaces = shared.networkInterfaces;
      shared.networkInterfaces = function () {
        const interfaces = origNetworkInterfaces.apply(this, arguments as any);
        if (interfaces && typeof interfaces === "object") {
          for (const key of Object.keys(interfaces)) {
            interfaces[key] = interfaces[key].filter(
              (i: any) => i.family !== "IPv6" && i.family !== 6,
            );
          }
        }
        return interfaces;
      };
    } else if (
      shared.networkInterfaces &&
      typeof shared.networkInterfaces === "object"
    ) {
      for (const key of Object.keys(shared.networkInterfaces)) {
        shared.networkInterfaces[key] = shared.networkInterfaces[key].filter(
          (i: any) => i.family !== "IPv6" && i.family !== 6,
        );
      }
    }
  }
} catch {}

export interface SendMailOptions {
  to: string;
  subject: string;
  html: string;
  from?: string;
}

export class MailService {
  private transporter: Transporter;

  constructor() {
    this.transporter = this.createTransporter(
      mailConfig.port || 587,
      mailConfig.secure,
    );
  }

  private createTransporter(port: number, secure: boolean): Transporter {
    return nodemailer.createTransport({
      host: mailConfig.host || "smtp.gmail.com",
      port,
      secure,
      requireTLS: !secure,
      family: 4, // Force IPv4 to prevent ENETUNREACH on environments without IPv6 routing
      auth: {
        user: mailConfig.auth.user,
        pass: mailConfig.auth.pass,
      },
      tls: {
        rejectUnauthorized: envConfig.nodeEnv === "development" ? false : true,
        servername: mailConfig.host || "smtp.gmail.com",
      },
      // Fast timeout: on cloud environments (e.g. Render free tier) with blocked SMTP ports, fail quickly
      connectionTimeout: 4000,
      greetingTimeout: 4000,
      socketTimeout: 5000,
    } as any);
  }

  private async sendViaResend(options: SendMailOptions): Promise<void> {
    // When using Resend testing domain (without verified custom domain), from must use onboarding@resend.dev
    const isCustomDomain =
      mailConfig.from.includes("@") &&
      !mailConfig.from.includes("gmail.com") &&
      !mailConfig.from.includes("resend.dev");
    const sender = isCustomDomain
      ? options.from || mailConfig.from
      : "App Template <onboarding@resend.dev>";

    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${mailConfig.resendApiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: sender,
        to: [options.to],
        subject: options.subject,
        html: options.html,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => "");
      throw new Error(`Resend API HTTP ${response.status}: ${errorText}`);
    }
  }

  private async sendViaWebhook(options: SendMailOptions): Promise<void> {
    const response = await fetch(mailConfig.mailWebhookUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        to: options.to,
        subject: options.subject,
        html: options.html,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => "");
      throw new Error(`Mail Webhook HTTP ${response.status}: ${errorText}`);
    }
  }

  private async dispatchEmail(options: SendMailOptions): Promise<void> {
    // 1. Tầng 1 (Ưu tiên): Gửi qua Resend HTTPS REST API (Port 443 không bao giờ bị chặn trên Cloud)
    if (mailConfig.resendApiKey) {
      try {
        await this.sendViaResend(options);
        return;
      } catch (resendError: any) {
        console.warn(
          `[MailService] Resend dispatch failed (${resendError?.message || resendError}). Falling back...`,
        );
      }
    }

    // 2. Tầng 2: Gửi qua Mail Webhook Relay (Port 443 e.g. Google Apps Script / Custom Relay)
    if (mailConfig.mailWebhookUrl) {
      try {
        await this.sendViaWebhook(options);
        return;
      } catch (webhookError: any) {
        console.warn(
          `[MailService] Webhook dispatch failed (${webhookError?.message || webhookError}). Falling back...`,
        );
      }
    }

    // 3. Tầng 3: Gửi qua SMTP trực tiếp qua IPv4 với timeout ngắn
    if (!mailConfig.auth.user || !mailConfig.auth.pass) {
      console.warn(
        "[MailService] SMTP credentials not configured. Skipping email dispatch.",
      );
      return;
    }

    const primaryPort = mailConfig.port || 587;
    const primarySecure = mailConfig.secure || primaryPort === 465;

    try {
      await this.transporter.sendMail({
        from: options.from || mailConfig.from,
        to: options.to,
        subject: options.subject,
        html: options.html,
      });
    } catch (smtpError: any) {
      // Nếu port chính (vd 587) thất bại do kết nối, thử lại với port thay thế (465 <-> 587) qua IPv4
      const altPort = primaryPort === 587 ? 465 : 587;
      const altSecure = altPort === 465;
      console.warn(
        `[MailService] SMTP dispatch failed on port ${primaryPort} (${smtpError?.message || smtpError}). Retrying on alternative port ${altPort} over IPv4...`,
      );
      const fallbackTransporter = this.createTransporter(altPort, altSecure);
      await fallbackTransporter.sendMail({
        from: options.from || mailConfig.from,
        to: options.to,
        subject: options.subject,
        html: options.html,
      });
    }
  }

  async sendVerificationEmail(email: string, token: string, fullName?: string) {
    const verificationUrl = `${mailConfig.verificationUrl}?token=${token}`;
    const safeFullName = escapeHtml(fullName) || "bạn";
    const mailOptions: SendMailOptions = {
      from: mailConfig.from,
      to: email,
      subject: "Xác thực tài khoản",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
          <h2 style="color: #4CAF50; text-align: center;">Chào mừng bạn đến với hệ thống!</h2>
          <p>Chào ${safeFullName},</p>
          <p>Cảm ơn bạn đã đăng ký tài khoản.</p>
          <p>Vui lòng xác nhận địa chỉ email của bạn để kích hoạt tài khoản bằng cách click vào nút bên dưới:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verificationUrl}" style="background-color: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Kích hoạt tài khoản</a>
          </div>
          <p>Hoặc bạn có thể sao chép liên kết dưới đây và dán vào trình duyệt của bạn:</p>
          <p style="word-break: break-all; color: #888888;">${verificationUrl}</p>
          <p>Liên kết này sẽ có hiệu lực trong vòng 24 giờ.</p>
          <hr style="border: 0; border-top: 1px solid #e0e0e0; margin: 20px 0;" />
          <p style="font-size: 12px; color: #888888; text-align: center;">Nếu bạn không thực hiện yêu cầu này, vui lòng bỏ qua email này.</p>
        </div>
      `,
    };

    if (!mailConfig.isConfigured) {
      if (envConfig.nodeEnv !== "production") {
        console.warn("-------- EMAIL VERIFICATION TOKEN (DEV MODE) --------");
        console.warn(`To: ${email}`);
        console.warn(`Link: ${verificationUrl}`);
        console.warn("----------------------------------------------------");
      }
      return;
    }

    try {
      await this.dispatchEmail(mailOptions);
    } catch (error) {
      console.error("[MailService] Failed to send verification email:", error);
      if (envConfig.nodeEnv !== "production") {
        console.warn("-------- VERIFICATION LINK FALLBACK (LOG) --------");
        console.warn(`To: ${email}`);
        console.warn(`Link: ${verificationUrl}`);
        console.warn("--------------------------------------------------");
      }
      throw error;
    }
  }

  async sendPasswordResetEmail(
    email: string,
    token: string,
    fullName?: string,
  ) {
    const resetUrl = `${mailConfig.resetPasswordUrl}?token=${token}`;
    const safeFullName = escapeHtml(fullName) || "bạn";
    const mailOptions: SendMailOptions = {
      from: mailConfig.from,
      to: email,
      subject: "Khôi phục mật khẩu tài khoản",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
          <h2 style="color: #f44336; text-align: center;">Khôi phục mật khẩu tài khoản</h2>
          <p>Chào ${safeFullName},</p>
          <p>Chúng tôi nhận được yêu cầu khôi phục mật khẩu cho tài khoản liên kết với địa chỉ email này.</p>
          <p>Vui lòng click vào nút bên dưới để tiến hành đặt lại mật khẩu mới:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" style="background-color: #f44336; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Đặt lại mật khẩu</a>
          </div>
          <p>Hoặc bạn có thể sao chép liên kết dưới đây và dán vào trình duyệt của bạn:</p>
          <p style="word-break: break-all; color: #888888;">${resetUrl}</p>
          <p>Liên kết này sẽ có hiệu lực trong vòng 1 giờ.</p>
          <hr style="border: 0; border-top: 1px solid #e0e0e0; margin: 20px 0;" />
          <p style="font-size: 12px; color: #888888; text-align: center;">Nếu bạn không thực hiện yêu cầu này, vui lòng bỏ qua email này. Mật khẩu của bạn sẽ không thay đổi.</p>
        </div>
      `,
    };

    if (!mailConfig.isConfigured) {
      if (envConfig.nodeEnv !== "production") {
        console.warn("-------- EMAIL PASSWORD RESET TOKEN (DEV MODE) --------");
        console.warn(`To: ${email}`);
        console.warn(`Link: ${resetUrl}`);
        console.warn("-------------------------------------------------------");
      }
      return;
    }

    try {
      await this.dispatchEmail(mailOptions);
    } catch (error) {
      console.error(
        "[MailService] Failed to send password reset email:",
        error,
      );
      if (envConfig.nodeEnv !== "production") {
        console.warn("-------- PASSWORD RESET LINK FALLBACK (LOG) --------");
        console.warn(`To: ${email}`);
        console.warn(`Link: ${resetUrl}`);
        console.warn("----------------------------------------------------");
      }
      throw error;
    }
  }

  async sendNewDeviceAlertEmail(
    email: string,
    details: { deviceName: string; ipAddress: string; loginTime: Date },
    fullName?: string,
  ) {
    const formattedDate = formatVietnamDateTime(details.loginTime);
    const safeFullName = escapeHtml(fullName) || "bạn";
    const safeDeviceName =
      escapeHtml(details.deviceName) || "Thiết bị không rõ";
    const safeIpAddress = escapeHtml(details.ipAddress) || "Không rõ";
    const mailOptions: SendMailOptions = {
      from: mailConfig.from,
      to: email,
      subject: "[Cảnh báo bảo mật] Đăng nhập từ thiết bị mới",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
          <h2 style="color: #f44336; text-align: center;">Cảnh báo đăng nhập thiết bị mới</h2>
          <p>Chào ${safeFullName},</p>
          <p>Hệ thống phát hiện tài khoản của bạn vừa được đăng nhập từ một thiết bị mới hoặc trình duyệt lạ.</p>
          
          <div style="background-color: #f9f9f9; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #f44336;">
            <p style="margin: 5px 0;"><strong>Thiết bị:</strong> ${safeDeviceName}</p>
            <p style="margin: 5px 0;"><strong>Địa chỉ IP:</strong> ${safeIpAddress}</p>
            <p style="margin: 5px 0;"><strong>Thời gian:</strong> ${formattedDate} (Giờ Việt Nam)</p>
          </div>

          <p>Nếu <strong>đây là bạn</strong>, bạn không cần làm gì cả. Thiết bị này sẽ tự động được thêm vào danh sách tin cậy.</p>
          <p style="color: #f44336; font-weight: bold;">Nếu KHÔNG phải bạn, vui lòng thực hiện các bước sau ngay lập tức để bảo vệ tài khoản:</p>
          <ol>
            <li>Đăng nhập vào tài khoản trên thiết bị chính chủ của bạn.</li>
            <li>Vào mục <strong>Cài đặt bảo mật > Quản lý thiết bị</strong> để đăng xuất từ xa phiên đăng nhập lạ này.</li>
            <li>Tiến hành <strong>Đổi mật khẩu</strong> tài khoản ngay lập tức.</li>
          </ol>
          <hr style="border: 0; border-top: 1px solid #e0e0e0; margin: 20px 0;" />
          <p style="font-size: 12px; color: #888888; text-align: center;">Đây là email tự động từ hệ thống bảo mật. Vui lòng không trả lời email này.</p>
        </div>
      `,
    };

    if (!mailConfig.isConfigured) {
      if (envConfig.nodeEnv !== "production") {
        console.warn("-------- NEW DEVICE ALERT EMAIL (DEV MODE) --------");
        console.warn(`To: ${email}`);
        console.warn(`Device: ${details.deviceName}`);
        console.warn(`IP: ${details.ipAddress}`);
        console.warn(`Time: ${formattedDate}`);
        console.warn("----------------------------------------------------");
      }
      return;
    }

    try {
      await this.dispatchEmail(mailOptions);
    } catch (error) {
      console.error(
        "[MailService] Failed to send new device alert email:",
        error,
      );
      // Non-critical alert, don't re-throw to avoid blocking login flow
    }
  }

  async sendAccountDeactivationEmail(
    email: string,
    token: string,
    fullName?: string,
  ) {
    const deactivationUrl = `${mailConfig.verificationUrl}/deactivate?token=${token}`;
    const safeFullName = escapeHtml(fullName) || "bạn";
    const mailOptions: SendMailOptions = {
      from: mailConfig.from,
      to: email,
      subject: "[Cảnh báo quan trọng] Xác nhận yêu cầu vô hiệu hóa tài khoản",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
          <h2 style="color: #d32f2f; text-align: center;">Yêu cầu vô hiệu hóa tài khoản</h2>
          <p>Chào ${safeFullName},</p>
          <p>Chúng tôi nhận được yêu cầu <strong>vô hiệu hóa tài khoản</strong> của bạn trên hệ thống.</p>
          
          <div style="background-color: #ffebee; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #d32f2f;">
            <p style="margin: 0; color: #b71c1c; font-weight: bold;">CẢNH BÁO QUAN TRỌNG:</p>
            <p style="margin: 5px 0 0 0; color: #b71c1c; font-size: 14px;">
              Khi xác nhận, tài khoản của bạn sẽ lập tức bị khóa, toàn bộ các phiên đăng nhập trên tất cả thiết bị sẽ bị hủy bỏ ngay lập tức và bạn sẽ không thể đăng nhập lại.
            </p>
          </div>

          <p>Nếu bạn thực sự muốn tiếp tục, vui lòng click vào nút xác nhận bên dưới:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${deactivationUrl}" style="background-color: #d32f2f; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Xác nhận vô hiệu hóa tài khoản</a>
          </div>

          <p>Hoặc sử dụng mã xác nhận (Token) trực tiếp qua ứng dụng:</p>
          <div style="background-color: #f5f5f5; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 14px; word-break: break-all; text-align: center;">
            ${token}
          </div>

          <p style="color: #666; font-size: 13px; margin-top: 15px;">Yêu cầu này sẽ tự động hết hạn sau <strong>15 phút</strong>.</p>
          <hr style="border: 0; border-top: 1px solid #e0e0e0; margin: 20px 0;" />
          <p style="font-size: 12px; color: #888888; text-align: center;">Nếu bạn KHÔNG thực hiện yêu cầu này, vui lòng bỏ qua email này và <strong>tiến hành đổi mật khẩu ngay lập tức</strong> để bảo vệ tài khoản của bạn.</p>
        </div>
      `,
    };

    if (!mailConfig.isConfigured) {
      if (envConfig.nodeEnv !== "production") {
        console.warn(
          "-------- EMAIL ACCOUNT DEACTIVATION TOKEN (DEV MODE) --------",
        );
        console.warn(`To: ${email}`);
        console.warn(`Token: ${token}`);
        console.warn(`Link: ${deactivationUrl}`);
        console.warn(
          "--------------------------------------------------------------",
        );
      }
      return;
    }

    try {
      await this.dispatchEmail(mailOptions);
    } catch (error) {
      console.error(
        "[MailService] Failed to send account deactivation email:",
        error,
      );
      if (envConfig.nodeEnv !== "production") {
        console.warn(
          "-------- ACCOUNT DEACTIVATION LINK FALLBACK (LOG) --------",
        );
        console.warn(`To: ${email}`);
        console.warn(`Token: ${token}`);
        console.warn(`Link: ${deactivationUrl}`);
        console.warn(
          "-----------------------------------------------------------",
        );
      }
      throw error;
    }
  }

  async sendOtpEmail(
    email: string,
    otp: string,
    details?: { purpose?: string; expiresInMinutes?: number },
    fullName?: string,
  ): Promise<void> {
    const purpose = details?.purpose || "xác thực tài khoản";
    const formattedMinutes =
      details?.expiresInMinutes && details.expiresInMinutes > 0
        ? details.expiresInMinutes
        : 15;
    const safeFullName = escapeHtml(fullName) || "bạn";
    const safePurpose = escapeHtml(purpose);
    const mailOptions: SendMailOptions = {
      from: mailConfig.from,
      to: email,
      subject: `[Mã xác thực] Mã OTP ${purpose}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 24px; border: 1px solid #e2e8f0; border-radius: 8px; background-color: #ffffff;">
          <h2 style="color: #0f172a; text-align: center;">Mã Xác Thực OTP</h2>
          <p>Chào ${safeFullName},</p>
          <p>Bạn vừa thực hiện yêu cầu <strong>${safePurpose}</strong>.</p>
          <div style="text-align: center; margin: 28px 0; padding: 18px; background-color: #f8fafc; border: 2px dashed #cbd5e1; border-radius: 8px;">
            <span style="font-size: 13px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; display: block; margin-bottom: 8px;">Mã OTP Của Bạn</span>
            <span style="font-family: 'Courier New', Courier, monospace; font-size: 36px; font-weight: bold; letter-spacing: 10px; color: #0284c7; display: inline-block;">${escapeHtml(otp)}</span>
            <span style="font-size: 12px; color: #dc2626; display: block; margin-top: 10px; font-weight: 500;">
              Mã có hiệu lực trong vòng ${formattedMinutes} phút
            </span>
          </div>
          <p style="font-size: 12px; color: #888888; text-align: center;">Vui lòng không chia sẻ mã này cho bất kỳ ai. Nếu bạn không thực hiện yêu cầu, hãy bỏ qua email này.</p>
        </div>
      `,
    };

    if (!mailConfig.isConfigured) {
      if (envConfig.nodeEnv !== "production") {
        console.warn("-------- OTP EMAIL (DEV MODE) --------");
        console.warn(`To: ${email}`);
        console.warn(`Purpose: ${purpose}`);
        console.warn(`OTP: ${otp}`);
        console.warn(`Expires In: ${formattedMinutes} minutes`);
        console.warn("---------------------------------------");
      }
      return;
    }

    try {
      await this.dispatchEmail(mailOptions);
    } catch (error) {
      console.error("[MailService] Failed to send OTP email:", error);
      if (envConfig.nodeEnv !== "production") {
        console.warn("-------- OTP FALLBACK LOG --------");
        console.warn(`To: ${email} | Purpose: ${purpose} | OTP: ${otp}`);
        console.warn("----------------------------------");
      }
      throw error;
    }
  }

  async sendRaw(
    to: string,
    subject: string,
    html: string,
    from?: string,
  ): Promise<void> {
    const mailOptions: SendMailOptions = {
      from: from || mailConfig.from,
      to,
      subject,
      html,
    };

    if (!mailConfig.isConfigured) {
      if (envConfig.nodeEnv !== "production") {
        console.warn("-------- RAW EMAIL (DEV MODE) --------");
        console.warn(`To: ${to}`);
        console.warn(`Subject: ${subject}`);
        console.warn("--------------------------------------");
      }
      return;
    }

    try {
      await this.dispatchEmail(mailOptions);
    } catch (error) {
      console.error(
        `[MailService] Failed to send email to ${to} (subject: ${subject}):`,
        error,
      );
      throw error;
    }
  }

  /**
   * Gửi Email cảnh báo vi phạm trang bị bảo hộ PPE cho cán bộ an toàn (D08.pdf)
   */
  async sendPpeViolationAlertEmail(
    to: string,
    data: {
      incidentId: string;
      violationType: string;
      severity: string;
      cameraCode?: string;
      siteName?: string;
      detectedAt?: Date | string;
      evidenceUrl?: string;
      description?: string;
    },
  ): Promise<void> {
    const formattedDate = formatVietnamDateTime(
      data.detectedAt instanceof Date ? data.detectedAt : new Date(data.detectedAt || Date.now()),
    );
    const severityColor =
      data.severity === NOTIFICATION_SEVERITY.CRITICAL
        ? "#e11d48"
        : data.severity === NOTIFICATION_SEVERITY.HIGH
          ? "#ea580c"
          : data.severity === NOTIFICATION_SEVERITY.MEDIUM
            ? "#d97706"
            : "#2563eb";

    const subject = `🚨 [${data.severity}] Cảnh báo vi phạm PPE: ${data.violationType} - ${data.siteName || "Công trường"}`;

    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
        <div style="background-color: ${severityColor}; color: white; padding: 15px; border-radius: 6px; text-align: center; margin-bottom: 20px;">
          <h2 style="margin: 0; font-size: 20px;">🚨 CẢNH BÁO VI PHẠM TRANG BỊ BẢO HỘ PPE</h2>
          <p style="margin: 5px 0 0 0; font-size: 14px; opacity: 0.9;">Mức độ nghiêm trọng: <strong>${escapeHtml(data.severity)}</strong></p>
        </div>

        <p style="font-size: 15px; color: #334155;">Kính gửi Cán bộ An toàn Lao động,</p>
        <p style="font-size: 14px; color: #475569; line-height: 1.6;">
          Hệ thống giám sát Smart PPE Monitoring vừa phát hiện sự cố vi phạm quy chuẩn an toàn lao động tại khu vực giám sát:
        </p>

        <table style="width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 14px;">
          <tr style="background-color: #f8fafc; border-bottom: 1px solid #e2e8f0;">
            <td style="padding: 10px; font-weight: bold; width: 35%; color: #475569;">Loại vi phạm:</td>
            <td style="padding: 10px; color: #0f172a; font-weight: bold;">${escapeHtml(data.violationType)}</td>
          </tr>
          <tr style="border-bottom: 1px solid #e2e8f0;">
            <td style="padding: 10px; font-weight: bold; color: #475569;">Công trường:</td>
            <td style="padding: 10px; color: #0f172a;">${escapeHtml(data.siteName || "Công trường chính")}</td>
          </tr>
          <tr style="background-color: #f8fafc; border-bottom: 1px solid #e2e8f0;">
            <td style="padding: 10px; font-weight: bold; color: #475569;">Vị trí Camera:</td>
            <td style="padding: 10px; color: #0f172a;">${escapeHtml(data.cameraCode || "CAM-DEFAULT")}</td>
          </tr>
          <tr style="border-bottom: 1px solid #e2e8f0;">
            <td style="padding: 10px; font-weight: bold; color: #475569;">Thời điểm phát hiện:</td>
            <td style="padding: 10px; color: #0f172a;">${escapeHtml(formattedDate)}</td>
          </tr>
          ${
            data.description
              ? `<tr style="background-color: #f8fafc; border-bottom: 1px solid #e2e8f0;">
                   <td style="padding: 10px; font-weight: bold; color: #475569;">Chi tiết:</td>
                   <td style="padding: 10px; color: #0f172a;">${escapeHtml(data.description)}</td>
                 </tr>`
              : ""
          }
        </table>

        ${
          data.evidenceUrl
            ? `<div style="text-align: center; margin: 25px 0;">
                 <img src="${escapeHtml(data.evidenceUrl)}" alt="Hình ảnh bằng chứng" style="max-width: 100%; height: auto; border-radius: 6px; border: 1px solid #cbd5e1;" />
                 <p style="font-size: 12px; color: #64748b; margin-top: 5px;">Hình ảnh bằng chứng trích xuất từ AI Vision</p>
               </div>`
            : ""
        }

        <p style="font-size: 13px; color: #64748b; margin-top: 30px; border-top: 1px solid #e2e8f0; padding-top: 15px;">
          Email này được gửi tự động từ <strong>Hệ thống Giám sát An toàn Công trường Thông minh Smart PPE Monitoring</strong>. Vui lòng đăng nhập hệ thống để xác nhận hoặc phân công xử lý sự cố.
        </p>
      </div>
    `;

    await this.sendRaw(to, subject, html);
  }
}

export const mailService = new MailService();

