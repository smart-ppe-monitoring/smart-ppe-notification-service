import { Request, Response, NextFunction } from "express";
import { NotificationService, notificationService } from "./notification.service";
import { sseManagerService } from "../../common/services/sse-manager.service";
import {
  ListNotificationsDto,
  SendNotificationDto,
  BroadcastNotificationDto,
  DispatchIncidentNotificationDto,
  UpdateNotificationPreferenceDto,
  ListEmailsDto,
  ListNotificationTemplatesDto,
  CreateNotificationTemplateDto,
  UpdateNotificationTemplateDto,
  PreviewNotificationTemplateDto,
  TestSendNotificationTemplateDto,
} from "./notification.dto";

export class NotificationController {
  private readonly service: NotificationService;

  constructor(service?: NotificationService) {
    this.service = service || notificationService;
  }

  // ─────────────────────────────────────────────
  // Realtime Stream & Stream Ticket
  // ─────────────────────────────────────────────

  createStreamTicket = (
    req: Request,
    res: Response,
    next: NextFunction,
  ): void => {
    try {
      const data = this.service.createStreamTicket(req.user);
      res.json({
        success: true,
        data,
        message: "Stream ticket generated successfully",
      });
    } catch (error) {
      next(error);
    }
  };

  stream = (req: Request, res: Response, next: NextFunction): void => {
    try {
      sseManagerService.registerClient(req.user.id, res, req);
    } catch (error) {
      next(error);
    }
  };

  // ─────────────────────────────────────────────
  // PPE Incident Notification Dispatch (BE-08)
  // ─────────────────────────────────────────────

  dispatchIncidentNotification = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const dto = req.body as DispatchIncidentNotificationDto;
      const result = await this.service.dispatchIncidentNotification(dto);
      res.status(201).json({
        success: true,
        message: "Phát cảnh báo sự cố vi phạm PPE thành công",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  };

  // ─────────────────────────────────────────────
  // User Notification Inbox Management
  // ─────────────────────────────────────────────

  list = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const dto = req.query as unknown as ListNotificationsDto;
      const { items, total, page, limit, totalPages } = await this.service.list(
        req.user.id,
        dto,
      );
      res.json({
        success: true,
        data: items,
        meta: { total, page, limit, totalPages },
      });
    } catch (error) {
      next(error);
    }
  };

  unreadCount = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = await this.service.getUnreadCount(req.user.id);
      res.json({ success: true, data: result });
    } catch (error) {
      next(error);
    }
  };

  markAsRead = async (req: Request, res: Response, next: NextFunction) => {
    try {
      await this.service.markAsRead(req.user.id, req.params.id);
      res.json({ success: true, message: "Đã đánh dấu thông báo là đã đọc" });
    } catch (error) {
      next(error);
    }
  };

  markAllAsRead = async (req: Request, res: Response, next: NextFunction) => {
    try {
      await this.service.markAllAsRead(req.user.id);
      res.json({ success: true, message: "Đã đánh dấu tất cả thông báo là đã đọc" });
    } catch (error) {
      next(error);
    }
  };

  delete = async (req: Request, res: Response, next: NextFunction) => {
    try {
      await this.service.delete(req.user.id, req.params.id);
      res.json({ success: true, message: "Đã xóa thông báo" });
    } catch (error) {
      next(error);
    }
  };

  // ─────────────────────────────────────────────
  // User Notification Preferences
  // ─────────────────────────────────────────────

  getPreferences = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const preferences = await this.service.getUserPreferences(req.user.id);
      res.json({
        success: true,
        data: preferences,
      });
    } catch (error) {
      next(error);
    }
  };

  updatePreference = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const dto = req.body as UpdateNotificationPreferenceDto;
      const updated = await this.service.updateUserPreference(req.user.id, dto);
      res.json({
        success: true,
        message: "Cập nhật cấu hình kênh nhận thông báo thành công",
        data: updated,
      });
    } catch (error) {
      next(error);
    }
  };

  // ─────────────────────────────────────────────
  // Legacy / Direct Send & Broadcast
  // ─────────────────────────────────────────────

  send = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const dto = req.body as SendNotificationDto;
      const result = await this.service.send(dto);
      res.status(201).json({
        success: true,
        message: "Phát thông báo thành công",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  };

  broadcast = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const dto = req.body as BroadcastNotificationDto;
      const result = await this.service.broadcast(dto);
      res.status(201).json({
        success: true,
        message: "Gửi thông báo toàn hệ thống thành công",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  };

  listEmails = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const dto = req.query as unknown as ListEmailsDto;
      const { items, total, page, limit, totalPages } =
        await this.service.listEmails(dto);
      res.json({
        success: true,
        data: items,
        meta: { total, page, limit, totalPages },
      });
    } catch (error) {
      next(error);
    }
  };

  retryEmail = async (req: Request, res: Response, next: NextFunction) => {
    try {
      await this.service.retryEmail(req.params.id);
      res.json({
        success: true,
        message: "Đã lên lịch thử lại gửi email",
      });
    } catch (error) {
      next(error);
    }
  };

  // ─────────────────────────────────────────────
  // Template Controller Handlers
  // ─────────────────────────────────────────────

  listTemplates = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const dto = req.query as unknown as ListNotificationTemplatesDto;
      const { items, total, page, limit, totalPages } =
        await this.service.listTemplates(dto);
      res.json({
        success: true,
        data: items,
        meta: { total, page, limit, totalPages },
      });
    } catch (error) {
      next(error);
    }
  };

  getTemplateByCode = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const template = await this.service.getTemplateByCode(req.params.code);
      res.json({ success: true, data: template });
    } catch (error) {
      next(error);
    }
  };

  createTemplate = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const dto = req.body as CreateNotificationTemplateDto;
      const template = await this.service.createTemplate(dto, {
        actorId: req.user.id,
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"],
      });
      res.status(201).json({
        success: true,
        message: "Tạo mẫu thông báo thành công",
        data: template,
      });
    } catch (error) {
      next(error);
    }
  };

  updateTemplate = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const dto = req.body as UpdateNotificationTemplateDto;
      const template = await this.service.updateTemplate(req.params.id, dto, {
        actorId: req.user.id,
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"],
      });
      res.json({
        success: true,
        message: "Cập nhật mẫu thông báo thành công",
        data: template,
      });
    } catch (error) {
      next(error);
    }
  };

  deleteTemplate = async (req: Request, res: Response, next: NextFunction) => {
    try {
      await this.service.deleteTemplate(req.params.id, {
        actorId: req.user.id,
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"],
      });
      res.json({
        success: true,
        message: "Đã xóa mẫu thông báo",
      });
    } catch (error) {
      next(error);
    }
  };

  previewTemplate = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const dto = req.body as PreviewNotificationTemplateDto;
      const preview = await this.service.previewTemplate(req.params.code, dto);
      res.json({
        success: true,
        data: preview,
      });
    } catch (error) {
      next(error);
    }
  };

  testSendTemplate = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      const dto = req.body as TestSendNotificationTemplateDto;
      const result = await this.service.testSendTemplate(
        req.params.code,
        req.user.id,
        dto,
      );
      res.json({
        success: true,
        message: result.message,
      });
    } catch (error) {
      next(error);
    }
  };
}

export const notificationController = new NotificationController();
