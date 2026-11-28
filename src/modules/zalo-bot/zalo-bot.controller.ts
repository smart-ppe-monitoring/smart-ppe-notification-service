import { Request, Response, NextFunction } from "express";
import {
  ZALO_BOT_MODE,
  ZALO_WEBHOOK_SECRET_HEADER,
} from "../../common/constants/notification.constant";
import { envConfig } from "../../config/env.config";
import { ERROR_CODE } from "../../common/errors/error-code";
import { SendZaloTestDto, SetZaloWebhookDto } from "./zalo-bot.dto";
import { ZaloBotService, zaloBotService } from "./zalo-bot.service";

export class ZaloBotController {
  private readonly service: ZaloBotService;

  constructor(service?: ZaloBotService) {
    this.service = service || zaloBotService;
  }

  verifyWebhookSecret = (req: Request, res: Response, next: NextFunction) => {
    if (envConfig.zaloBot.mode === ZALO_BOT_MODE.DISABLED) {
      res.status(503).json({
        success: false,
        message: "Zalo Bot webhook is disabled",
        code: ERROR_CODE.SERVICE_UNAVAILABLE,
      });
      return;
    }

    const incomingSecret = req.headers[ZALO_WEBHOOK_SECRET_HEADER];
    if (!this.service.verifyWebhookSecret(incomingSecret)) {
      res.status(403).json({
        success: false,
        message: "Unauthorized",
        code: ERROR_CODE.UNAUTHORIZED,
      });
      return;
    }
    next();
  };

  handleWebhook = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const outcome = await this.service.processUpdate(req.body);
      res.status(200).json({
        ok: true,
        message: "Success",
        data: outcome,
      });
    } catch (error) {
      next(error);
    }
  };

  getStatus = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const data = await this.service.getStatus(req.user.id);
      res.json({
        success: true,
        data,
      });
    } catch (error) {
      next(error);
    }
  };

  generateLinkToken = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const data = await this.service.generateLinkToken(req.user.id);
      res.status(201).json({
        success: true,
        message: "Đã tạo mã liên kết Zalo Bot thành công",
        data,
      });
    } catch (error) {
      next(error);
    }
  };

  unlink = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const data = await this.service.unlinkAccount(req.user.id);
      res.json({
        success: true,
        message: "Đã hủy liên kết tài khoản Zalo Bot",
        data,
      });
    } catch (error) {
      next(error);
    }
  };

  sendTest = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const dto = (req.body || {}) as SendZaloTestDto;
      const data = await this.service.sendTestMessage(req.user.id, dto);
      res.json({
        success: true,
        message: "Đã gửi tin nhắn kiểm thử tới Zalo Bot thành công",
        data,
      });
    } catch (error) {
      next(error);
    }
  };

  getAdminInfo = async (_req: Request, res: Response, next: NextFunction) => {
    try {
      const data = await this.service.getAdminBotInfo();
      res.json({
        success: true,
        data,
      });
    } catch (error) {
      next(error);
    }
  };

  configureWebhook = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const dto = req.body as SetZaloWebhookDto;
      const data = await this.service.configureWebhook(dto);
      res.json({
        success: true,
        message: "Cấu hình Zalo Bot Webhook thành công",
        data,
      });
    } catch (error) {
      next(error);
    }
  };

  removeWebhook = async (_req: Request, res: Response, next: NextFunction) => {
    try {
      const data = await this.service.removeWebhook();
      res.json({
        success: true,
        message: "Đã xóa cấu hình Zalo Bot Webhook",
        data,
      });
    } catch (error) {
      next(error);
    }
  };
}

export const zaloBotController = new ZaloBotController();
