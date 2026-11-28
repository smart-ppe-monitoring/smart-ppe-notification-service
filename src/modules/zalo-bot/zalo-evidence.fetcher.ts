import path from "node:path";
import { envConfig } from "../../config/env.config";
import { GATEWAY_HEADERS } from "../../common/constants/gateway.constant";
import {
  extractInternalEvidenceId,
  isTrustedMinioEvidenceUrl,
} from "../../common/helpers/url.helper";

export interface ZaloEvidenceAsset {
  buffer: Buffer;
  mimeType: string;
  fileName: string;
}

export type ZaloEvidenceFetcher = (
  evidenceUrl: string,
  incidentId?: string,
) => Promise<ZaloEvidenceAsset | null>;

export const MAX_ZALO_EVIDENCE_IMAGE_BYTES = 10 * 1024 * 1024;

export const ALLOWED_ZALO_EVIDENCE_IMAGE_MIMES = new Set([
  "image/jpeg",
  "image/jpg",
  "image/png",
  "image/webp",
  "image/gif",
]);

function sanitizeEvidenceFileName(rawHeader: string | null): string {
  if (!rawHeader) return "evidence.jpg";
  let decoded = rawHeader;
  try {
    decoded = decodeURIComponent(rawHeader);
  } catch {
    return "evidence.jpg";
  }
  const base = path.basename(decoded).replace(/[\r\n\x00-\x1f\x7f"\\/]/g, "_").trim();
  if (!base || base === "." || base === "..") return "evidence.jpg";
  return base.slice(0, 120);
}

async function readBoundedImageResponse(
  res: Response,
  fallbackName: string,
): Promise<ZaloEvidenceAsset | null> {
  if (!res.ok) return null;

  const contentType = (res.headers.get("content-type") || "image/jpeg")
    .split(";")[0]
    .trim()
    .toLowerCase();
  if (!ALLOWED_ZALO_EVIDENCE_IMAGE_MIMES.has(contentType)) {
    await res.body?.cancel().catch(() => {});
    return null;
  }

  const contentLengthHeader = res.headers.get("content-length");
  if (contentLengthHeader) {
    const declaredBytes = Number(contentLengthHeader);
    if (
      Number.isFinite(declaredBytes) &&
      declaredBytes > MAX_ZALO_EVIDENCE_IMAGE_BYTES
    ) {
      await res.body?.cancel().catch(() => {});
      return null;
    }
  }

  const arrayBuffer = await res.arrayBuffer();
  const buffer = Buffer.from(arrayBuffer);
  if (buffer.length === 0 || buffer.length > MAX_ZALO_EVIDENCE_IMAGE_BYTES) {
    return null;
  }

  const fileName = res.headers.get("x-evidence-filename")
    ? sanitizeEvidenceFileName(res.headers.get("x-evidence-filename"))
    : fallbackName;

  return { buffer, mimeType: contentType, fileName };
}

/**
 * Tạo fetcher tải ảnh bằng chứng nội bộ M2M cho Zalo Bot (chống cross-incident BOLA, SVG XSS, redirect SSRF & quá tải RAM).
 */
export function createInternalEvidenceFetcher(
  fetchImpl: typeof fetch = fetch,
): ZaloEvidenceFetcher {
  return async function fetchInternalEvidence(
    evidenceUrl: string,
    incidentId?: string,
  ): Promise<ZaloEvidenceAsset | null> {
    if (!evidenceUrl || typeof evidenceUrl !== "string") return null;

    try {
      const evidenceId = extractInternalEvidenceId(evidenceUrl);
      if (evidenceId) {
        if (!incidentId) {
          return null;
        }
        const incidentBaseUrl = (envConfig.incident.serviceUrl || "").replace(
          /\/+$/,
          "",
        );
        if (!incidentBaseUrl || !envConfig.internalService.token) {
          return null;
        }

        const headers: Record<string, string> = {
          Accept: "image/*",
          [GATEWAY_HEADERS.INTERNAL_SERVICE_TOKEN]:
            envConfig.internalService.token,
        };
        if (envConfig.gateway.internalSecret) {
          headers[GATEWAY_HEADERS.INTERNAL_SECRET] =
            envConfig.gateway.internalSecret;
        }

        const res = await fetchImpl(
          `${incidentBaseUrl}/api/v1/incidents/internal/evidences/${encodeURIComponent(evidenceId)}/content?incidentId=${encodeURIComponent(incidentId)}`,
          {
            method: "GET",
            headers,
            redirect: "error",
            signal: AbortSignal.timeout(5_000),
          },
        );
        return readBoundedImageResponse(res, "evidence.jpg");
      }

      if (
        isTrustedMinioEvidenceUrl(
          evidenceUrl,
          envConfig.minio.endpoint,
          envConfig.minio.bucketEvidences,
        )
      ) {
        const res = await fetchImpl(evidenceUrl, {
          method: "GET",
          redirect: "error",
          signal: AbortSignal.timeout(5_000),
        });
        return readBoundedImageResponse(res, "evidence.jpg");
      }

      return null;
    } catch {
      return null;
    }
  };
}

export const defaultInternalEvidenceFetcher = createInternalEvidenceFetcher();
