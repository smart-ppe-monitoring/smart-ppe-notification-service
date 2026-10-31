import { Request, Response, NextFunction } from "express";
import { AppError } from "../common/errors/app-error";
import { ERROR_CODE } from "../common/errors/error-code";
import { ROLES } from "../common/constants/role.constant";
import {
  MAINTENANCE_STATUS,
  DEFAULT_MAINTENANCE_CONFIG,
} from "../common/constants/maintenance.constant";
import { maintenanceCacheService } from "../common/services/maintenance-cache.service";
import { getSharedRateLimitRedisClient } from "./rate-limit.middleware";

export interface MaintenanceGuardOptions {
  isMaintenanceMode?: boolean | (() => boolean | Promise<boolean>);
  exemptPaths?: (string | RegExp)[];
}

const DEFAULT_EXEMPT_PATHS: (string | RegExp)[] = [
  "/health",
  /^\/api\/v1\/notifications\/health/,
  /^\/notifications\/health/,
  /^\/openapi\.json/,
  /^\/api-docs/,
  /^\/api\/docs/,
  /security\.txt/,
];

/**
 * SEC-35: Middleware bảo vệ chế độ bảo trì hệ thống (Maintenance Guard).
 * Chặn các yêu cầu HTTP khi hệ thống đang trong giai đoạn bảo trì nâng cấp,
 * chỉ cho phép liveness/health probe và người dùng quản trị (ADMIN / MAINTENANCE_BYPASS).
 */
export function maintenanceGuard(options?: MaintenanceGuardOptions) {
  const exemptPaths = options?.exemptPaths ?? DEFAULT_EXEMPT_PATHS;

  return async (
    req: Request,
    _res: Response,
    next: NextFunction,
  ): Promise<void> => {
    try {
      let isMaintenance = false;

      // 1. Kiểm tra cấu hình override hoặc inject từ options (dành cho testing)
      if (typeof options?.isMaintenanceMode === "function") {
        isMaintenance = await options.isMaintenanceMode();
      } else if (typeof options?.isMaintenanceMode === "boolean") {
        isMaintenance = options.isMaintenanceMode;
      } else if (
        process.env.MAINTENANCE_MODE === "true" ||
        process.env.MAINTENANCE_ENABLED === "true"
      ) {
        // 2. Kiểm tra qua biến môi trường
        isMaintenance = true;
      } else {
        // 3. Kiểm tra qua maintenanceCacheService
        try {
          const config = await maintenanceCacheService.getConfig();
          if (
            config?.enabled === true ||
            config?.status === MAINTENANCE_STATUS.MAINTENANCE
          ) {
            isMaintenance = true;
          }
        } catch {
          // Bỏ qua lỗi cache service
        }

        // 4. Kiểm tra qua Redis cache nếu khả dụng
        if (!isMaintenance) {
          const redis = getSharedRateLimitRedisClient();
          if (redis) {
            try {
              const raw = await redis.get("system:maintenance");
              if (raw) {
                const parsed = JSON.parse(raw);
                if (
                  parsed?.enabled === true ||
                  parsed?.status === MAINTENANCE_STATUS.MAINTENANCE
                ) {
                  isMaintenance = true;
                }
              }
            } catch {
              // Bỏ qua lỗi kết nối Redis
            }
          }
        }
      }

      if (!isMaintenance) {
        return next();
      }

      // Kiểm tra xem route hiện tại có thuộc danh sách miễn trừ (liveness, health check) không
      const path = req.originalUrl || req.url || req.path || "";
      const isExempt = exemptPaths.some((pattern) => {
        if (typeof pattern === "string") {
          return path.startsWith(pattern) || path === pattern;
        }
        return pattern.test(path);
      });

      if (isExempt) {
        return next();
      }

      // Quyền Quản trị viên (Admin) hoặc có quyền bypass được phép đi qua bảo trì
      const user = (req as any).user;
      const isAdmin =
        user?.role === ROLES.ADMIN ||
        user?.role === "ADMIN" ||
        user?.permissions?.includes("MAINTENANCE_BYPASS") ||
        user?.permissions?.includes("MAINTENANCE_MANAGE");

      if (isAdmin) {
        return next();
      }

      next(
        new AppError(
          DEFAULT_MAINTENANCE_CONFIG.message,
          503,
          ERROR_CODE.SYSTEM_MAINTENANCE,
        ),
      );
    } catch (err) {
      next(err);
    }
  };
}
