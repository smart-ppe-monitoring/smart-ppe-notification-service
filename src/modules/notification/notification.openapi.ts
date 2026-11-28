import { openapiRegistry } from "../../config/openapi/openapi.registry";
import {
  sendNotificationSchema,
  broadcastNotificationSchema,
  listNotificationsSchema,
  notificationIdParamSchema,
  createNotificationTemplateSchema,
  updateNotificationTemplateSchema,
  templateCodeParamSchema,
  templateIdParamSchema,
  previewNotificationTemplateSchema,
  listNotificationTemplatesSchema,
  listEmailsSchema,
  emailIdParamSchema,
  testSendNotificationTemplateSchema,
  updateNotificationPreferenceSchema,
  dispatchIncidentNotificationSchema,
} from "./notification.validation";
import { z } from "zod";

export function registerNotificationOpenApi(): void {
  openapiRegistry.register("SendNotificationRequest", sendNotificationSchema);
  openapiRegistry.register(
    "BroadcastNotificationRequest",
    broadcastNotificationSchema,
  );
  openapiRegistry.register(
    "UpdateNotificationPreferenceRequest",
    updateNotificationPreferenceSchema,
  );
  openapiRegistry.register(
    "DispatchIncidentNotificationRequest",
    dispatchIncidentNotificationSchema,
  );
  openapiRegistry.register(
    "CreateTemplateRequest",
    createNotificationTemplateSchema,
  );
  openapiRegistry.register(
    "UpdateTemplateRequest",
    updateNotificationTemplateSchema,
  );
  openapiRegistry.register(
    "PreviewTemplateRequest",
    previewNotificationTemplateSchema,
  );
  openapiRegistry.register(
    "TestSendTemplateRequest",
    testSendNotificationTemplateSchema,
  );

  // ── Web Notifications ────────────────────────────────────────────────────────

  // POST /notifications/stream-ticket
  openapiRegistry.registerPath({
    method: "post",
    path: "/notifications/stream-ticket",
    tags: ["Notifications"],
    summary: "Tạo vé một lần (One-Time Ticket) để kết nối xác thực Server-Sent Events (SSE)",
    security: [{ BearerAuth: [] }],
    responses: {
      200: {
        description: "Tạo ticket thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              data: z.object({
                ticket: z.string().openapi({ example: "st_01923456789abcdef" }),
                expiresIn: z.number().openapi({ example: 60 }),
              }),
              message: z.string().openapi({ example: "Stream ticket generated successfully" }),
            }),
          },
        },
      },
      401: {
        description: "Chưa xác thực (Yêu cầu JWT)",
      },
    },
  });

  // GET /notifications/stream
  openapiRegistry.registerPath({
    method: "get",
    path: "/notifications/stream",
    tags: ["Notifications"],
    summary:
      "Mở luồng Server-Sent Events (SSE) nhận thông báo & sự kiện thời gian thực",
    security: [{ BearerAuth: [] }],
    responses: {
      200: {
        description:
          "Luồng SSE được thiết lập thành công (Content-Type: text/event-stream)",
        content: {
          "text/event-stream": {
            schema: z.string().openapi({
              example:
                'event: notification:new\ndata: {"title":"New alert"}\n\n',
            }),
          },
        },
      },
      401: {
        description:
          "Chưa xác thực (Yêu cầu JWT qua Cookie, Bearer header hoặc ?token=...)",
      },
    },
  });

  // GET /notifications
  openapiRegistry.registerPath({
    method: "get",
    path: "/notifications",

    tags: ["Notifications"],
    summary: "Danh sách thông báo của người dùng hiện tại",
    description:
      "Mặc định chỉ trả về các kênh hiển thị hộp thư web (IN_APP, WEB) chưa lưu trữ (archivedAt = null) và tự động gộp trường deliveredChannels nếu thông báo được phát đa kênh (VD: IN_APP + EMAIL).",
    security: [{ BearerAuth: [] }],
    request: { query: listNotificationsSchema },
    responses: {
      200: {
        description: "Lấy danh sách thông báo thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              data: z.array(
                z.object({
                  id: z.string().uuid(),
                  title: z.string(),
                  content: z.string(),
                  channel: z.string(),
                  deliveredChannels: z.array(z.string()).optional(),
                  type: z.string(),
                  actionUrl: z.string().nullable(),
                  isRead: z.boolean(),
                  readAt: z.string().datetime().nullable(),
                  archivedAt: z.string().datetime().nullable().optional(),
                  createdAt: z.string().datetime(),
                }),
              ),
              meta: z.object({
                total: z.number(),
                page: z.number(),
                limit: z.number(),
                totalPages: z.number(),
              }),
            }),
          },
        },
      },
    },
  });

  // GET /notifications/unread-count
  openapiRegistry.registerPath({
    method: "get",
    path: "/notifications/unread-count",
    tags: ["Notifications"],
    summary: "Số lượng thông báo chưa đọc",
    security: [{ BearerAuth: [] }],
    responses: {
      200: {
        description: "Lấy số lượng chưa đọc thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              data: z.object({ unreadCount: z.number() }),
            }),
          },
        },
      },
    },
  });

  // POST /notifications/send
  openapiRegistry.registerPath({
    method: "post",
    path: "/notifications/send",
    tags: ["Notifications"],
    summary: "Gửi thông báo tới một người dùng cụ thể (Web / Email)",
    security: [{ BearerAuth: [] }],
    request: {
      body: {
        content: { "application/json": { schema: sendNotificationSchema } },
      },
    },
    responses: {
      201: {
        description: "Gửi thông báo thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              data: z.object({
                webNotification: z.record(z.unknown()).optional(),
                emailNotification: z.record(z.unknown()).optional(),
              }),
            }),
          },
        },
      },
    },
  });

  // POST /notifications/broadcast
  openapiRegistry.registerPath({
    method: "post",
    path: "/notifications/broadcast",
    tags: ["Notifications"],
    summary: "Gửi thông báo quảng bá (Broadcast) tới toàn bộ người dùng",
    security: [{ BearerAuth: [] }],
    request: {
      body: {
        content: {
          "application/json": { schema: broadcastNotificationSchema },
        },
      },
    },
    responses: {
      200: {
        description: "Gửi broadcast thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              data: z.object({ count: z.number() }),
            }),
          },
        },
      },
    },
  });

  // PATCH /notifications/:id/read
  openapiRegistry.registerPath({
    method: "patch",
    path: "/notifications/{id}/read",
    tags: ["Notifications"],
    summary: "Đánh dấu thông báo là đã đọc",
    security: [{ BearerAuth: [] }],
    request: { params: notificationIdParamSchema },
    responses: {
      200: {
        description: "Đánh dấu đã đọc thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              data: z.object({ id: z.string().uuid(), isRead: z.boolean() }),
            }),
          },
        },
      },
    },
  });

  // PATCH /notifications/read-all
  openapiRegistry.registerPath({
    method: "patch",
    path: "/notifications/read-all",
    tags: ["Notifications"],
    summary: "Đánh dấu toàn bộ thông báo của tôi là đã đọc",
    security: [{ BearerAuth: [] }],
    responses: {
      200: {
        description: "Đánh dấu tất cả đã đọc thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              data: z.object({ count: z.number() }),
            }),
          },
        },
      },
    },
  });

  // PATCH /notifications/archive-read
  openapiRegistry.registerPath({
    method: "patch",
    path: "/notifications/archive-read",
    tags: ["Notifications"],
    summary: "Lưu trữ toàn bộ thông báo đã đọc của người dùng hiện tại",
    security: [{ BearerAuth: [] }],
    responses: {
      200: {
        description: "Lưu trữ thông báo đã đọc thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              message: z.string(),
              data: z.object({ archivedCount: z.number() }),
            }),
          },
        },
      },
    },
  });

  // PATCH /notifications/:id/archive
  openapiRegistry.registerPath({
    method: "patch",
    path: "/notifications/{id}/archive",
    tags: ["Notifications"],
    summary: "Lưu trữ một thông báo",
    security: [{ BearerAuth: [] }],
    request: { params: notificationIdParamSchema },
    responses: {
      200: {
        description: "Đã lưu trữ thông báo",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              message: z.string(),
            }),
          },
        },
      },
      404: { description: "Không tìm thấy thông báo" },
    },
  });

  // PATCH /notifications/:id/unarchive
  openapiRegistry.registerPath({
    method: "patch",
    path: "/notifications/{id}/unarchive",
    tags: ["Notifications"],
    summary: "Khôi phục một thông báo khỏi mục lưu trữ",
    security: [{ BearerAuth: [] }],
    request: { params: notificationIdParamSchema },
    responses: {
      200: {
        description: "Đã khôi phục thông báo khỏi lưu trữ",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              message: z.string(),
            }),
          },
        },
      },
      404: { description: "Không tìm thấy thông báo" },
    },
  });

  // DELETE /notifications/:id
  openapiRegistry.registerPath({
    method: "delete",
    path: "/notifications/{id}",
    tags: ["Notifications"],
    summary: "Xóa một thông báo",
    security: [{ BearerAuth: [] }],
    request: { params: notificationIdParamSchema },
    responses: {
      200: {
        description: "Xóa thông báo thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              message: z
                .string()
                .openapi({ example: "Xóa thông báo thành công" }),
            }),
          },
        },
      },
    },
  });

  // ── Templates ───────────────────────────────────────────────────────────────

  // GET /notifications/templates
  openapiRegistry.registerPath({
    method: "get",
    path: "/notifications/templates",
    tags: ["Notification Templates"],
    summary: "Danh sách mẫu thông báo / email",
    security: [{ BearerAuth: [] }],
    request: { query: listNotificationTemplatesSchema },
    responses: {
      200: {
        description: "Lấy danh sách mẫu thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              data: z.array(
                z.object({
                  id: z.string().uuid(),
                  code: z.string(),
                  name: z.string(),
                  description: z.string().nullable(),
                  channels: z.array(z.string()),
                  subject: z.string().nullable(),
                  title: z.string().nullable(),
                  content: z.string(),
                  variables: z.array(z.string()),
                  isSystem: z.boolean(),
                  isActive: z.boolean(),
                  createdAt: z.string().datetime(),
                }),
              ),
              meta: z.object({
                total: z.number(),
                page: z.number(),
                limit: z.number(),
                totalPages: z.number(),
              }),
            }),
          },
        },
      },
    },
  });

  // POST /notifications/templates
  openapiRegistry.registerPath({
    method: "post",
    path: "/notifications/templates",
    tags: ["Notification Templates"],
    summary: "Tạo mẫu thông báo mới",
    security: [{ BearerAuth: [] }],
    request: {
      body: {
        content: {
          "application/json": { schema: createNotificationTemplateSchema },
        },
      },
    },
    responses: {
      201: {
        description: "Tạo mẫu thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              data: z.object({
                id: z.string().uuid(),
                code: z.string(),
                name: z.string(),
              }),
            }),
          },
        },
      },
    },
  });

  // POST /notifications/templates/:code/preview
  openapiRegistry.registerPath({
    method: "post",
    path: "/notifications/templates/{code}/preview",
    tags: ["Notification Templates"],
    summary: "Xem trước mẫu thông báo khi điền biến dữ liệu",
    security: [{ BearerAuth: [] }],
    request: {
      params: templateCodeParamSchema,
      body: {
        content: {
          "application/json": { schema: previewNotificationTemplateSchema },
        },
      },
    },
    responses: {
      200: {
        description: "Xem trước thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              data: z.object({
                subject: z.string().nullable(),
                title: z.string().nullable(),
                content: z.string(),
                html: z.string().optional(),
              }),
            }),
          },
        },
      },
    },
  });

  // GET /notifications/templates/:code
  openapiRegistry.registerPath({
    method: "get",
    path: "/notifications/templates/{code}",
    tags: ["Notification Templates"],
    summary: "Chi tiết mẫu thông báo theo mã code",
    security: [{ BearerAuth: [] }],
    request: { params: templateCodeParamSchema },
    responses: {
      200: {
        description: "Lấy chi tiết mẫu thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              data: z.object({
                id: z.string().uuid(),
                code: z.string(),
                name: z.string(),
                description: z.string().nullable(),
                channels: z.array(z.string()),
                subject: z.string().nullable(),
                title: z.string().nullable(),
                content: z.string(),
                variables: z.array(z.string()),
                isSystem: z.boolean(),
                isActive: z.boolean(),
              }),
            }),
          },
        },
      },
    },
  });

  // PUT /notifications/templates/:id
  openapiRegistry.registerPath({
    method: "put",
    path: "/notifications/templates/{id}",
    tags: ["Notification Templates"],
    summary: "Cập nhật mẫu thông báo theo ID",
    security: [{ BearerAuth: [] }],
    request: {
      params: templateIdParamSchema,
      body: {
        content: {
          "application/json": { schema: updateNotificationTemplateSchema },
        },
      },
    },
    responses: {
      200: {
        description: "Cập nhật mẫu thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              message: z.string().openapi({
                example: "Notification template updated successfully",
              }),
              data: z.record(z.unknown()),
            }),
          },
        },
      },
      404: { description: "Không tìm thấy mẫu thông báo" },
    },
  });

  // DELETE /notifications/templates/:id
  openapiRegistry.registerPath({
    method: "delete",
    path: "/notifications/templates/{id}",
    tags: ["Notification Templates"],
    summary: "Xóa mẫu thông báo theo ID",
    security: [{ BearerAuth: [] }],
    request: { params: templateIdParamSchema },
    responses: {
      200: {
        description: "Xóa mẫu thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              message: z
                .string()
                .openapi({ example: "Xóa mẫu thông báo thành công" }),
            }),
          },
        },
      },
      404: { description: "Không tìm thấy mẫu thông báo" },
    },
  });

  // POST /notifications/templates/:code/test-send
  openapiRegistry.registerPath({
    method: "post",
    path: "/notifications/templates/{code}/test-send",
    tags: ["Notification Templates"],
    summary: "Gửi thử nghiệm mẫu thông báo tới email hoặc web",
    security: [{ BearerAuth: [] }],
    request: {
      params: templateCodeParamSchema,
      body: {
        content: {
          "application/json": { schema: testSendNotificationTemplateSchema },
        },
      },
    },
    responses: {
      200: {
        description: "Gửi thử nghiệm thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              message: z
                .string()
                .openapi({ example: "Test email sent successfully" }),
            }),
          },
        },
      },
      400: { description: "Mẫu không khả dụng hoặc tham số không đúng" },
    },
  });

  // ── Emails ──────────────────────────────────────────────────────────────────

  // GET /notifications/emails
  openapiRegistry.registerPath({
    method: "get",
    path: "/notifications/emails",
    tags: ["Email Notifications"],
    summary: "Danh sách lịch sử gửi email và trạng thái hàng đợi",
    description:
      "Hỗ trợ lọc theo status, toEmail, userId và khoảng thời gian fromDate / toDate (DD/MM/YYYY, YYYY-MM-DD hoặc ISO 8601). Yêu cầu quyền NOTIFICATION_TEMPLATE_MANAGE hoặc NOTIFICATION_UPDATE.",
    security: [{ BearerAuth: [] }],
    request: { query: listEmailsSchema },
    responses: {
      200: {
        description: "Lấy lịch sử email thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              data: z.array(
                z.object({
                  id: z.string().uuid(),
                  toEmail: z.string().email(),
                  subject: z.string(),
                  templateKey: z.string(),
                  status: z.string(),
                  attempts: z.number(),
                  lastError: z.string().nullable(),
                  sentAt: z.string().datetime().nullable(),
                  createdAt: z.string().datetime(),
                }),
              ),
              meta: z.object({
                total: z.number(),
                page: z.number(),
                limit: z.number(),
                totalPages: z.number(),
              }),
            }),
          },
        },
      },
      403: {
        description:
          "Thiếu quyền NOTIFICATION_TEMPLATE_MANAGE hoặc NOTIFICATION_UPDATE",
      },
      422: { description: "Tham số lọc ngày hoặc truy vấn không hợp lệ" },
    },
  });

  // POST /notifications/emails/:id/retry
  openapiRegistry.registerPath({
    method: "post",
    path: "/notifications/emails/{id}/retry",
    tags: ["Email Notifications"],
    summary: "Gửi lại (Retry) một email thất bại trong hàng đợi",
    description:
      "Yêu cầu quyền NOTIFICATION_TEMPLATE_MANAGE hoặc NOTIFICATION_UPDATE.",
    security: [{ BearerAuth: [] }],
    request: { params: emailIdParamSchema },
    responses: {
      200: {
        description: "Đã đưa email vào hàng đợi gửi lại",
        content: {
          "application/json": {
            schema: z.object({
               success: z.boolean().openapi({ example: true }),
               message: z
                 .string()
                 .openapi({ example: "Email scheduled for retry" }),
            }),
          },
        },
      },
      403: {
        description:
          "Thiếu quyền NOTIFICATION_TEMPLATE_MANAGE hoặc NOTIFICATION_UPDATE",
      },
      404: { description: "Không tìm thấy email" },
    },
  });

  // ── PPE Incident Notification & Preferences ──────────────────────────────────

  // GET /notifications/preferences
  openapiRegistry.registerPath({
    method: "get",
    path: "/notifications/preferences",
    tags: ["Notification Preferences"],
    summary: "Xem cấu hình kênh nhận thông báo cá nhân (In-App, Email, ngưỡng severity)",
    security: [{ BearerAuth: [] }],
    responses: {
      200: {
        description: "Lấy cấu hình kênh nhận thông báo thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.array(
                z.object({
                  id: z.string().uuid(),
                  userId: z.string().uuid(),
                  channel: z.string(),
                  enabled: z.boolean(),
                  severityThreshold: z.string(),
                }),
              ),
            }),
          },
        },
      },
    },
  });

  // PUT /notifications/preferences
  openapiRegistry.registerPath({
    method: "put",
    path: "/notifications/preferences",
    tags: ["Notification Preferences"],
    summary: "Cập nhật cấu hình kênh nhận thông báo cá nhân (IN_APP, EMAIL, ZALO_BOT)",
    description:
      "Cập nhật trạng thái bật/tắt và ngưỡng mức độ nghiêm trọng cho kênh thông báo cá nhân. Hỗ trợ 3 kênh IN_APP, EMAIL và ZALO_BOT; các kênh chưa triển khai như WEBHOOK, WEB sẽ bị từ chối.",
    security: [{ BearerAuth: [] }],
    request: {
      body: {
        content: {
          "application/json": { schema: updateNotificationPreferenceSchema },
        },
      },
    },
    responses: {
      200: {
        description: "Cập nhật cấu hình kênh nhận thông báo thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              message: z.string(),
              data: z.any(),
            }),
          },
        },
      },
      422: {
        description:
          "Kênh thông báo không được hỗ trợ (chỉ chấp nhận IN_APP, EMAIL hoặc ZALO_BOT)",
      },
    },
  });

  // POST /notifications/trigger-incident
  openapiRegistry.registerPath({
    method: "post",
    path: "/notifications/trigger-incident",
    tags: ["PPE Incident Notifications"],
    summary: "Kích hoạt phát cảnh báo sự cố vi phạm PPE cho cán bộ an toàn (D08.pdf)",
    security: [{ BearerAuth: [] }],
    request: {
      body: {
        content: {
          "application/json": { schema: dispatchIncidentNotificationSchema },
        },
      },
    },
    responses: {
      201: {
        description: "Phát cảnh báo sự cố vi phạm PPE thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              message: z.string(),
              data: z.object({
                incidentId: z.string(),
                dispatchedCount: z.number(),
                channels: z.array(z.string()),
              }),
            }),
          },
        },
      },
    },
  });
}
