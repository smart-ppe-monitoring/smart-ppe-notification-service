import { Router } from "express";
import { authMiddleware } from "../../middlewares/auth.middleware";
import { requirePermission } from "../../middlewares/permission.middleware";
import { authRateLimitMiddleware } from "../../middlewares/rate-limit.middleware";
import { validate } from "../../middlewares/validate.middleware";
import { PERMISSIONS } from "../../common/constants/permission.constant";
import { zaloBotController } from "./zalo-bot.controller";
import {
  sendZaloTestSchema,
  setZaloWebhookSchema,
  zaloWebhookUpdateSchema,
} from "./zalo-bot.validation";

export const zaloWebhookRouter = Router();

// Public Webhook endpoint nhận sự kiện từ Zalo Bot Platform (xác thực X-Bot-Api-Secret-Token trước khi validate payload)
zaloWebhookRouter.post(
  "/",
  zaloBotController.verifyWebhookSecret,
  validate(zaloWebhookUpdateSchema),
  zaloBotController.handleWebhook,
);

export const zaloBotRouter = Router();
zaloBotRouter.use(authMiddleware);

zaloBotRouter.get("/status", zaloBotController.getStatus);
zaloBotRouter.post(
  "/link-token",
  authRateLimitMiddleware,
  zaloBotController.generateLinkToken,
);
zaloBotRouter.delete("/binding", zaloBotController.unlink);
zaloBotRouter.post(
  "/test",
  authRateLimitMiddleware,
  validate(sendZaloTestSchema),
  zaloBotController.sendTest,
);

// Admin quản trị cấu hình Zalo Bot & Webhook
zaloBotRouter.get(
  "/admin/info",
  requirePermission(PERMISSIONS.NOTIFICATION_TEMPLATE_MANAGE),
  zaloBotController.getAdminInfo,
);
zaloBotRouter.post(
  "/admin/webhook",
  requirePermission(PERMISSIONS.NOTIFICATION_TEMPLATE_MANAGE),
  validate(setZaloWebhookSchema),
  zaloBotController.configureWebhook,
);
zaloBotRouter.delete(
  "/admin/webhook",
  requirePermission(PERMISSIONS.NOTIFICATION_TEMPLATE_MANAGE),
  zaloBotController.removeWebhook,
);
