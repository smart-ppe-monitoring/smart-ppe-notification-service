import { envConfig } from "./env.config";

export const mailConfig = {
  get appUrl(): string {
    if (process.env.APP_URL) {
      return process.env.APP_URL.replace(/\/+$/, "");
    }
    const renderUrl =
      process.env.RENDER_EXTERNAL_URL || envConfig.renderExternalUrl;
    if (renderUrl) {
      return renderUrl.replace(/\/+$/, "");
    }
    return (envConfig.appUrl || "http://localhost:3000").replace(/\/+$/, "");
  },
  host: envConfig.mail.host,
  port: envConfig.mail.port,
  secure: envConfig.mail.secure,
  auth: {
    user: envConfig.mail.user,
    pass: envConfig.mail.pass,
  },
  from: envConfig.mail.from,
  get verificationUrl(): string {
    return `${this.appUrl}/verify-email`;
  },
  get resetPasswordUrl(): string {
    return `${this.appUrl}/reset-password`;
  },
  get deactivationUrl(): string {
    return `${this.appUrl}/deactivate`;
  },
  get resendApiKey(): string {
    return process.env.RESEND_API_KEY || envConfig.mail.resendApiKey;
  },
  get mailWebhookUrl(): string {
    return process.env.MAIL_WEBHOOK_URL || envConfig.mail.webhookUrl;
  },
  get webhookSecret(): string {
    return process.env.MAIL_WEBHOOK_SECRET || envConfig.mail.webhookSecret;
  },
  get isConfigured(): boolean {
    return Boolean(
      this.resendApiKey ||
      this.mailWebhookUrl ||
      (this.auth.user && this.auth.pass),
    );
  },
};
