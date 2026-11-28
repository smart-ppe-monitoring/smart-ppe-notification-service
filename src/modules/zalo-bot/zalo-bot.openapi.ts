import { openapiRegistry } from "../../config/openapi/openapi.registry";
import {
  sendZaloTestSchema,
  setZaloWebhookSchema,
  zaloWebhookUpdateSchema,
} from "./zalo-bot.validation";

export function registerZaloBotOpenApi(): void {
  openapiRegistry.register("SetZaloWebhookRequest", setZaloWebhookSchema);
  openapiRegistry.register("SendZaloTestRequest", sendZaloTestSchema);
  openapiRegistry.register("ZaloWebhookUpdateRequest", zaloWebhookUpdateSchema);

  openapiRegistry.registerPath({
    method: "get",
    path: "/notifications/zalo/status",
    tags: ["Zalo Bot"],
    summary: "Lấy trạng thái cấu hình Zalo Bot và liên kết hiện tại của người dùng",
    security: [{ BearerAuth: [] }],
    responses: {
      200: { description: "Trạng thái liên kết Zalo Bot" },
    },
  });

  openapiRegistry.registerPath({
    method: "post",
    path: "/notifications/zalo/link-token",
    tags: ["Zalo Bot"],
    summary: "Sinh mã liên kết một lần (/link CODE, TTL 10 phút) để kết nối tài khoản Zalo",
    security: [{ BearerAuth: [] }],
    responses: {
      201: { description: "Sinh mã liên kết thành công" },
    },
  });

  openapiRegistry.registerPath({
    method: "delete",
    path: "/notifications/zalo/binding",
    tags: ["Zalo Bot"],
    summary: "Hủy liên kết tài khoản Zalo Bot hiện tại",
    security: [{ BearerAuth: [] }],
    responses: {
      200: { description: "Đã hủy liên kết" },
    },
  });

  openapiRegistry.registerPath({
    method: "post",
    path: "/notifications/zalo/test",
    tags: ["Zalo Bot"],
    summary: "Gửi tin nhắn kiểm thử tới cuộc trò chuyện Zalo đã liên kết",
    security: [{ BearerAuth: [] }],
    request: {
      body: {
        content: {
          "application/json": { schema: sendZaloTestSchema },
        },
      },
    },
    responses: {
      200: { description: "Gửi tin nhắn kiểm thử thành công" },
      400: { description: "Chưa liên kết Zalo Bot" },
    },
  });

  openapiRegistry.registerPath({
    method: "post",
    path: "/notifications/zalo/webhook",
    tags: ["Zalo Bot"],
    summary: "Webhook nhận sự kiện từ Zalo Bot Platform (xác thực X-Bot-Api-Secret-Token)",
    request: {
      body: {
        content: {
          "application/json": { schema: zaloWebhookUpdateSchema },
        },
      },
    },
    responses: {
      200: { description: "Xử lý webhook thành công" },
      403: { description: "Sai hoặc thiếu X-Bot-Api-Secret-Token" },
    },
  });

  openapiRegistry.registerPath({
    method: "get",
    path: "/notifications/zalo/admin/info",
    tags: ["Zalo Bot"],
    summary: "Lấy thông tin Bot (getMe) và trạng thái Webhook (getWebhookInfo) cho Admin",
    security: [{ BearerAuth: [] }],
    responses: {
      200: { description: "Thông tin Zalo Bot" },
    },
  });

  openapiRegistry.registerPath({
    method: "post",
    path: "/notifications/zalo/admin/webhook",
    tags: ["Zalo Bot"],
    summary: "Đăng ký Webhook HTTPS công khai cho Zalo Bot Platform (setWebhook)",
    security: [{ BearerAuth: [] }],
    request: {
      body: {
        content: {
          "application/json": { schema: setZaloWebhookSchema },
        },
      },
    },
    responses: {
      200: { description: "Đăng ký webhook thành công" },
    },
  });

  openapiRegistry.registerPath({
    method: "delete",
    path: "/notifications/zalo/admin/webhook",
    tags: ["Zalo Bot"],
    summary: "Xóa cấu hình Webhook của Zalo Bot Platform (deleteWebhook)",
    security: [{ BearerAuth: [] }],
    responses: {
      200: { description: "Đã xóa webhook" },
    },
  });
}
