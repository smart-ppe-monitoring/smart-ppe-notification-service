import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { jwtConfig } from "../config/jwt.config";
import { AppError } from "../common/errors/app-error";
import { ERROR_CODE } from "../common/errors/error-code";
import { JWT_PURPOSE, JWT_ALGORITHM } from "../common/constants/jwt.constant";

/**
 * SEC-39: Danh sách các endpoint stream hợp lệ được phép nhận query ticket / token.
 * Tuyệt đối không dùng hậu tố lỏng lẻo cleanPath.endsWith('/stream') để tránh rò rỉ token qua URL ở các route khác (như /templates/:code).
 */
export const ALLOWED_STREAM_ENDPOINTS = new Set([
  "/api/v1/notifications/stream",
  "/notifications/stream",
  "/stream",
]);

export function isStreamEndpoint(req: Request): boolean {
  const path = req.path || "";
  const originalUrl = (req.originalUrl || "").split("?")[0];
  const baseUrl = req.baseUrl || "";
  const combined = (baseUrl + path).split("?")[0];

  return (
    ALLOWED_STREAM_ENDPOINTS.has(combined) ||
    ALLOWED_STREAM_ENDPOINTS.has(originalUrl) ||
    ALLOWED_STREAM_ENDPOINTS.has(path)
  );
}

export function extractTokenFromRequest(req: Request): string | undefined {
  let token = req.cookies?.accessToken;
  if (!token) {
    const authHeader = req.headers?.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    }
  }

  const isAllowedQueryToken = isStreamEndpoint(req);

  if (!token && isAllowedQueryToken) {
    const queryToken = req.query?.ticket || req.query?.token;
    if (typeof queryToken === "string") {
      token = queryToken;
    }
  }
  return token;
}

export async function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const isAllowedQueryToken = isStreamEndpoint(req);

  if (!isAllowedQueryToken && req.query?.token) {
    next(
      new AppError(
        "Không được phép truyền token xác thực qua query string trên API thông thường để tránh rò rỉ qua log và browser history",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      ),
    );
    return;
  }

  const token = extractTokenFromRequest(req);

  if (!token) {
    next(new AppError("Unauthorized", 401, ERROR_CODE.UNAUTHORIZED));
    return;
  }

  const isStreamPath = isAllowedQueryToken;

  try {
    let payload: any;
    if (isStreamPath && jwtConfig.tempSecret) {
      try {
        payload = jwt.verify(token, jwtConfig.tempSecret, {
          algorithms: [JWT_ALGORITHM.HS256],
        });
      } catch {
        // Fallback to standard token verification below
      }
    }

    if (!payload) {
      const decoded = jwt.decode(token, { complete: true });
      if (!decoded || typeof decoded !== "object" || !decoded.header) {
        next(new AppError("Token không hợp lệ", 401, ERROR_CODE.UNAUTHORIZED));
        return;
      }

      const { alg } = decoded.header;
      if (alg !== JWT_ALGORITHM.RS256) {
        next(
          new AppError(
            `Thuật toán '${alg}' không được chấp nhận. Hệ thống chỉ hỗ trợ RS256.`,
            401,
            ERROR_CODE.UNAUTHORIZED,
          ),
        );
        return;
      }

      if (!jwtConfig.publicKey) {
        next(
          new AppError(
            "Cấu hình khóa công khai RS256 chưa sẵn sàng",
            500,
            ERROR_CODE.INTERNAL_SERVER_ERROR,
          ),
        );
        return;
      }

      payload = jwt.verify(token, jwtConfig.publicKey, {
        algorithms: [JWT_ALGORITHM.RS256],
      });
    }

    if (!payload || typeof payload !== "object") {
      next(new AppError("Token không hợp lệ", 401, ERROR_CODE.UNAUTHORIZED));
      return;
    }

    // SEC: Token SSE ticket chỉ được dùng cho /stream, tuyệt đối không được dùng cho route khác
    if (
      payload.purpose === JWT_PURPOSE.SSE_STREAM_TICKET &&
      !isStreamPath
    ) {
      next(
        new AppError(
          "SSE Stream Ticket chỉ dùng cho kết nối SSE stream",
          401,
          ERROR_CODE.UNAUTHORIZED,
        ),
      );
      return;
    }

    // SEC-02: Chặn token tạm thời (2FA verification / temp token) hoặc token sai mục đích truy cập tài nguyên bảo vệ
    if (
      payload.purpose === JWT_PURPOSE.TWO_FACTOR ||
      payload.type === "TEMP" ||
      (payload.purpose &&
        payload.purpose !== JWT_PURPOSE.ACCESS &&
        !(isStreamPath && payload.purpose === JWT_PURPOSE.SSE_STREAM_TICKET))
    ) {
      next(
        new AppError(
          "Token không hợp lệ để truy cập tài nguyên được bảo vệ",
          401,
          ERROR_CODE.UNAUTHORIZED,
        ),
      );
      return;
    }

    // SEC-08: Chặn token có cờ mustChangePassword truy cập satellite services
    if (
      payload.mustChangePassword === true ||
      payload.mustChangePassword === "true"
    ) {
      next(
        new AppError(
          "Bạn bắt buộc phải đổi mật khẩu trước khi thực hiện các thao tác khác trên hệ thống",
          403,
          ERROR_CODE.FORBIDDEN,
        ),
      );
      return;
    }

    req.user = {
      id: payload.id || payload.sub,
      email: payload.email,
      role: payload.role,
      roleId: payload.roleId,
      permissions: Array.isArray(payload.permissions)
        ? payload.permissions
        : undefined,
    };

    next();
  } catch (error) {
    if (error instanceof AppError) {
      next(error);
      return;
    }
    next(new AppError("Token xác thực không hợp lệ hoặc đã hết hạn", 401, ERROR_CODE.UNAUTHORIZED));
  }
}
