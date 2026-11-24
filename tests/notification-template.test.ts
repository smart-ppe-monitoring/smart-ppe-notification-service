import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { renderTemplateString } from "../src/common/helpers/template.helper";
import { EmailTemplateService } from "../src/common/services/email-template.service";
import {
  createNotificationTemplateSchema,
  updateNotificationTemplateSchema,
  previewNotificationTemplateSchema,
} from "../src/modules/notification/notification.validation";
import { NotificationService } from "../src/modules/notification/notification.service";
import { NotificationRepository } from "../src/modules/notification/notification.repository";
import { MailService } from "../src/common/services/mail.service";
import { SseManagerService } from "../src/common/services/sse-manager.service";
import { NOTIFICATION_CHANNEL } from "../src/common/constants/notification.constant";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";

describe("Notification Template Rendering & Helpers", () => {
  it("should interpolate placeholders correctly in renderTemplateString", () => {
    const template = "Xin chào {{fullName}}, mã xác thực của bạn là: {{code}}!";
    const result = renderTemplateString(template, {
      fullName: "Nguyễn Văn A",
      code: "889900",
    });

    assert.equal(
      result,
      "Xin chào Nguyễn Văn A, mã xác thực của bạn là: 889900!",
    );
  });

  it("should handle placeholders with surrounding whitespaces inside braces", () => {
    const template = "Chào {{  name  }}, số dư của bạn là {{ balance }} đ.";
    const result = renderTemplateString(template, {
      name: "Tester",
      balance: 500000,
    });

    assert.equal(result, "Chào Tester, số dư của bạn là 500000 đ.");
  });

  it("should replace undefined/null variables with empty string gracefully", () => {
    const template = "Hello {{firstName}} {{lastName}}!";
    const result = renderTemplateString(template, {
      firstName: "John",
      lastName: null,
    });

    assert.equal(result, "Hello John !");
  });

  it("should return empty string when empty template is provided", () => {
    assert.equal(renderTemplateString(""), "");
  });

  it("should escape HTML special characters by default in renderTemplateString (SEC-04)", () => {
    const template = "User: {{name}} has device: {{device}}";
    const result = renderTemplateString(template, {
      name: '<script>alert("XSS")</script>',
      device: 'My <Laptop> & "Phone"',
    });

    assert.equal(
      result,
      "User: &lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt; has device: My &lt;Laptop&gt; &amp; &quot;Phone&quot;",
    );
  });

  it("should allow raw HTML interpolation when escapeHtml option is explicitly false", () => {
    const template = "Content: {{htmlContent}}";
    const result = renderTemplateString(
      template,
      { htmlContent: "<b>Bold Text</b>" },
      { escapeHtml: false },
    );

    assert.equal(result, "Content: <b>Bold Text</b>");
  });
});

describe("Email Template Service Standards", () => {
  const service = new EmailTemplateService();

  it("should wrap body HTML with responsive base layout", () => {
    const layout = service.baseLayout(
      "Tiêu đề kiểm tra",
      "<p>Nội dung kiểm tra</p>",
    );
    assert.match(layout, /<h2.*>Tiêu đề kiểm tra<\/h2>/);
    assert.match(layout, /<p>Nội dung kiểm tra<\/p>/);
    assert.match(layout, /max-width: 600px/);
  });

  it("should synchronously render VERIFY_EMAIL template", () => {
    const result = service.render("VERIFY_EMAIL", {
      token: "test-uuid-token",
      fullName: "Nguyễn Văn B",
    });

    assert.equal(result.subject, "Xác thực tài khoản của bạn");
    assert.match(result.html, /Nguyễn Văn B/);
    assert.match(result.html, /test-uuid-token/);
  });

  it("should escape malicious deviceName and ipAddress in newDeviceAlert (SEC-04)", () => {
    const result = service.newDeviceAlert({
      fullName: "Admin",
      deviceName: '<script>fetch("http://evil.com")</script>',
      ipAddress: "127.0.0.1",
      time: "2026-09-14 01:00:00",
    });

    assert.equal(result.html.includes("<script>fetch"), false);
    assert.match(result.html, /&lt;script&gt;fetch/);
  });
});

describe("Notification Template Zod Validation", () => {
  it("should validate valid create template input", () => {
    const valid = createNotificationTemplateSchema.safeParse({
      code: "PAYMENT_SUCCESS",
      name: "Thanh toán thành công",
      description: "Gửi khi đơn hàng thanh toán thành công",
      channels: ["WEB", "EMAIL"],
      subject: "Xác nhận thanh toán đơn hàng {{orderId}}",
      title: "Thanh toán thành công",
      content: "Đơn hàng {{orderId}} trị giá {{amount}} đã thanh toán.",
      variables: ["orderId", "amount"],
      isActive: true,
    });

    assert.equal(valid.success, true);
  });

  it("should reject invalid template code format (lowercase or invalid characters)", () => {
    const invalid = createNotificationTemplateSchema.safeParse({
      code: "payment-success!",
      name: "Thanh toán",
      channels: ["WEB"],
      content: "Nội dung",
    });

    assert.equal(invalid.success, false);
  });

  it("should validate preview template schema", () => {
    const parsed = previewNotificationTemplateSchema.safeParse({
      variables: {
        orderId: "ORD-12345",
        amount: 250000,
      },
    });

    assert.equal(parsed.success, true);
  });
});

describe("NotificationService.testSendTemplate EMAIL recipient resolution", () => {
  const userId = "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a61";
  const emailTemplate = {
    id: "018f3a2b-c4d5-7e8f-9a0b-1c2d3e4f5a99",
    code: "PPE_VIOLATION_ALERT",
    name: "Cảnh báo PPE",
    channel: NOTIFICATION_CHANNEL.EMAIL,
    subjectTemplate: "Cảnh báo {{siteName}}",
    contentTemplate: "Phát hiện vi phạm {{violationType}}",
    status: "ACTIVE",
  };

  it("should dispatch EMAIL template using dto.toEmail", async () => {
    const sentEmails: Array<{ to: string; subject: string; html: string }> = [];
    const createdRecords: any[] = [];

    const service = new NotificationService(
      {
        findTemplateByCode: async () => emailTemplate,
        createManyNotifications: async (records: any[]) => {
          createdRecords.push(...records);
          return { count: records.length };
        },
      } as unknown as NotificationRepository,
      {
        sendRaw: async (to: string, subject: string, html: string) => {
          sentEmails.push({ to, subject, html });
        },
      } as unknown as MailService,
      { sendToUser: () => {} } as unknown as SseManagerService,
      new EmailTemplateService(),
      undefined,
      undefined,
      { isFeatureEnabled: async () => true },
    );

    const res = await service.testSendTemplate(
      "PPE_VIOLATION_ALERT",
      userId,
      {
        toEmail: "tester@smartsite.vn",
        variables: { siteName: "Landmark", violationType: "NO_HELMET" },
      },
      "fallback@smartsite.vn",
    );

    assert.match(res.message, /PPE_VIOLATION_ALERT/);
    assert.equal(createdRecords.length, 1);
    assert.equal(sentEmails.length, 1);
    assert.equal(sentEmails[0].to, "tester@smartsite.vn");
    assert.equal(sentEmails[0].subject, "Cảnh báo Landmark");
    assert.match(sentEmails[0].html, /NO_HELMET/);
  });

  it("should fall back to actor email when dto.toEmail is omitted", async () => {
    const sentEmails: Array<{ to: string; subject: string }> = [];

    const service = new NotificationService(
      {
        findTemplateByCode: async () => emailTemplate,
        createManyNotifications: async (records: any[]) => ({
          count: records.length,
        }),
      } as unknown as NotificationRepository,
      {
        sendRaw: async (to: string, subject: string) => {
          sentEmails.push({ to, subject });
        },
      } as unknown as MailService,
      { sendToUser: () => {} } as unknown as SseManagerService,
      new EmailTemplateService(),
      undefined,
      undefined,
      { isFeatureEnabled: async () => true },
    );

    await service.testSendTemplate(
      "PPE_VIOLATION_ALERT",
      userId,
      {
        variables: { siteName: "Site B", violationType: "NO_VEST" },
      },
      "admin@smartsite.vn",
    );

    assert.equal(sentEmails.length, 1);
    assert.equal(sentEmails[0].to, "admin@smartsite.vn");
  });

  it("should throw 400 VALIDATION_ERROR when both dto.toEmail and fallbackEmail are absent for EMAIL template", async () => {
    const service = new NotificationService(
      {
        findTemplateByCode: async () => emailTemplate,
      } as unknown as NotificationRepository,
      {} as unknown as MailService,
      { sendToUser: () => {} } as unknown as SseManagerService,
      new EmailTemplateService(),
      undefined,
      undefined,
      { isFeatureEnabled: async () => true },
    );

    await assert.rejects(
      () =>
        service.testSendTemplate("PPE_VIOLATION_ALERT", userId, {
          variables: { siteName: "Site C", violationType: "NO_HELMET" },
        }),
      (err: any) =>
        err instanceof AppError &&
        err.statusCode === 400 &&
        err.code === ERROR_CODE.VALIDATION_ERROR,
    );
  });
});
