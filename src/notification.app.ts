import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import {
  errorMiddleware,
  notFoundMiddleware,
} from "./middlewares/error.middleware";
import notificationRoute from "./modules/notification/notification.route";
import { rateLimitMiddleware } from "./middlewares/rate-limit.middleware";
import { requestIdMiddleware } from "./middlewares/request-id.middleware";
import { maintenanceGuard } from "./middlewares/maintenance.middleware";
import { envConfig } from "./config/env.config";

/**
 * Express Application cho Notification Microservice (Phase 5: First Satellite Service)
 *
 * Đảm nhiệm:
 * - REST API cho Notification domain (/api/v1/notifications/*)
 * - Server-Sent Events (SSE) stream (/stream) & stream ticket
 * - Quản lý Notification Templates & Email Logs
 * - Health check cho API Gateway (Traefik) load balancer
 */
const notificationApp = express();

notificationApp.set("trust proxy", envConfig.trustProxy);

// 1. Distributed Tracing & Security Headers
notificationApp.use(requestIdMiddleware);
notificationApp.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
  }),
);

// 2. CORS Handling
const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    const allowed = envConfig.cors.allowedOrigins.map((o) =>
      o.replace(/\/+$/, ""),
    );
    if (!origin) {
      callback(null, true);
      return;
    }
    const cleanOrigin = origin.replace(/\/+$/, "");
    if (allowed.includes("*")) {
      if (envConfig.nodeEnv !== "production") {
        callback(null, true);
        return;
      }
      console.error(
        "[CORS] CORS_ALLOWED_ORIGINS=* is not permitted in production.",
      );
      callback(null, false);
      return;
    }
    if (allowed.includes(cleanOrigin)) {
      callback(null, true);
    } else {
      callback(null, false);
    }
  },
  credentials: true,
};
notificationApp.use(cors(corsOptions));
notificationApp.use(
  morgan(envConfig.nodeEnv === "production" ? "combined" : "dev"),
);
notificationApp.use(express.json({ limit: "2mb" }));
notificationApp.use(express.urlencoded({ extended: true, limit: "2mb" }));
notificationApp.use(cookieParser());

// 3. Health check endpoints cho Traefik Gateway & Monitoring
const healthHandler = (_req: express.Request, res: express.Response) => {
  res.status(200).json({
    status: "ok",
    service: "notification-service",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
};

notificationApp.get("/health", healthHandler);
notificationApp.get("/api/v1/notifications/health", healthHandler);
notificationApp.get("/notifications/health", healthHandler);

// 4. Mount Notification Routes (dual-mount hỗ trợ cả prefix /api/v1/notifications và /notifications)
notificationApp.use(
  "/api/v1/notifications",
  rateLimitMiddleware,
  maintenanceGuard(),
  notificationRoute,
);
notificationApp.use(
  "/notifications",
  rateLimitMiddleware,
  maintenanceGuard(),
  notificationRoute,
);

// 5. Error handling middlewares
notificationApp.use(notFoundMiddleware);
notificationApp.use(errorMiddleware);

export default notificationApp;
