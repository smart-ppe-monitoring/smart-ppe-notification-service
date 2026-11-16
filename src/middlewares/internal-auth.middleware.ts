import crypto from "node:crypto";
import { Request, Response, NextFunction } from "express";
import { envConfig } from "../config/env.config";
import { GATEWAY_HEADERS } from "../common/constants/gateway.constant";
import { AppError } from "../common/errors/app-error";
import { ERROR_CODE } from "../common/errors/error-code";

function extractInternalToken(req: Request): string {
  const headerToken = req.headers[GATEWAY_HEADERS.INTERNAL_SERVICE_TOKEN];
  if (typeof headerToken === "string" && headerToken.trim().length > 0) {
    return headerToken.trim();
  }
  if (Array.isArray(headerToken) && headerToken[0]?.trim()) {
    return headerToken[0].trim();
  }

  const authHeader = req.headers.authorization;
  if (typeof authHeader === "string" && authHeader.startsWith("Bearer ")) {
    return authHeader.slice(7).trim();
  }

  return "";
}

function safeTokenMatch(expected: string, provided: string): boolean {
  if (!expected || !provided) {
    return false;
  }
  const expectedDigest = crypto.createHash("sha256").update(expected).digest();
  const providedDigest = crypto.createHash("sha256").update(provided).digest();
  return crypto.timingSafeEqual(expectedDigest, providedDigest);
}

/**
 * Factory middleware xác thực M2M bằng INTERNAL_SERVICE_TOKEN (fail-closed).
 */
export function createRequireInternalServiceToken(
  tokenResolver: string | (() => string),
) {
  return function requireInternalServiceTokenMiddleware(
    req: Request,
    _res: Response,
    next: NextFunction,
  ): void {
    const expectedToken =
      typeof tokenResolver === "function" ? tokenResolver() : tokenResolver;

    if (!expectedToken || expectedToken.trim().length === 0) {
      next(
        new AppError(
          "Internal service token is not configured",
          503,
          ERROR_CODE.SERVICE_UNAVAILABLE,
        ),
      );
      return;
    }

    const providedToken = extractInternalToken(req);
    if (!providedToken) {
      next(
        new AppError(
          "Internal service authentication required",
          401,
          ERROR_CODE.UNAUTHORIZED,
        ),
      );
      return;
    }

    if (!safeTokenMatch(expectedToken.trim(), providedToken)) {
      next(
        new AppError(
          "Invalid internal service token",
          403,
          ERROR_CODE.FORBIDDEN,
        ),
      );
      return;
    }

    next();
  };
}

export const requireInternalServiceToken = createRequireInternalServiceToken(
  () => envConfig.internalService.token,
);
