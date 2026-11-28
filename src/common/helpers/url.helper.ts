import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { AppError } from "../errors/app-error";
import { ERROR_CODE } from "../errors/error-code";

/**
 * URL & SSRF Helper
 *
 * Cung cấp các tiện ích kiểm tra URL, phát hiện Private IP / Loopback / Cloud Metadata,
 * phân giải DNS kiểm tra IP thật sự đằng sau domain (chống DNS Rebinding),
 * và kiểm tra chuỗi chuyển hướng HTTP redirect (chống SSRF qua redirect chaining).
 */

/**
 * Kiểm tra xem một địa chỉ IP (IPv4 hoặc IPv6) có thuộc dải private, loopback,
 * link-local, multicast, cloud metadata hoặc reserved hay không.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  if (!ip || typeof ip !== "string") return true;

  const trimmed = ip.trim().toLowerCase();
  const clean =
    trimmed.startsWith("[") && trimmed.endsWith("]")
      ? trimmed.slice(1, -1)
      : trimmed;

  // ── Xử lý IPv4-mapped / IPv4-compatible / NAT64 IPv6 (cả dạng dotted lẫn hex sau chuẩn hóa URL) ──
  const dottedEmbedded = clean.match(
    /^(?:::ffff:|(?:0+:){5}ffff:|::|64:ff9b::)(\d+\.\d+\.\d+\.\d+)$/i,
  );
  if (dottedEmbedded) {
    return isPrivateOrReservedIp(dottedEmbedded[1]);
  }

  const hexEmbedded = clean.match(
    /^(?:::ffff:|(?:0+:){5}ffff:|::|64:ff9b::|::ffff:0:)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i,
  );
  if (hexEmbedded) {
    const hi = parseInt(hexEmbedded[1], 16);
    const lo = parseInt(hexEmbedded[2], 16);
    const mappedIpv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
    return isPrivateOrReservedIp(mappedIpv4);
  }

  // ── IPv4 Check ──
  const ipv4Parts = clean.split(".");
  if (ipv4Parts.length === 4 && ipv4Parts.every((p) => /^\d+$/.test(p))) {
    const [a, b, c, d] = ipv4Parts.map(Number);
    if (
      [a, b, c, d].some((octet) => octet < 0 || octet > 255 || isNaN(octet))
    ) {
      return true;
    }

    // 0.0.0.0/8 — Unspecified / "This host on this network"
    if (a === 0) return true;
    // 10.0.0.0/8 — Private Class A
    if (a === 10) return true;
    // 100.64.0.0/10 — Carrier-grade NAT (CGN)
    if (a === 100 && b >= 64 && b <= 127) return true;
    // 127.0.0.0/8 — Loopback
    if (a === 127) return true;
    // 169.254.0.0/16 — Link-local / Cloud Provider Instance Metadata (AWS, GCP, Azure, DO, etc.)
    if (a === 169 && b === 254) return true;
    // 172.16.0.0/12 — Private Class B (172.16.0.0 – 172.31.255.255)
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.0.0.0/24 — IETF Protocol Assignments
    if (a === 192 && b === 0 && c === 0) return true;
    // 192.0.2.0/24 — TEST-NET-1
    if (a === 192 && b === 0 && c === 2) return true;
    // 192.168.0.0/16 — Private Class C
    if (a === 192 && b === 168) return true;
    // 198.18.0.0/15 — Network benchmark tests
    if (a === 198 && (b === 18 || b === 19)) return true;
    // 198.51.100.0/24 — TEST-NET-2
    if (a === 198 && b === 51 && c === 100) return true;
    // 203.0.113.0/24 — TEST-NET-3
    if (a === 203 && b === 0 && c === 113) return true;
    // 224.0.0.0/4 — Multicast (224.0.0.0 – 239.255.255.255)
    if (a >= 224 && a <= 239) return true;
    // 240.0.0.0/4 — Reserved for future use & 255.255.255.255 Broadcast
    if (a >= 240) return true;

    return false;
  }

  // ── IPv6 Check ──
  if (clean.includes(":")) {
    // Loopback ::1
    if (clean === "::1" || clean === "0:0:0:0:0:0:0:1") return true;
    // Unspecified ::
    if (clean === "::" || clean === "0:0:0:0:0:0:0:0") return true;
    // Discard-Only 100::/64, NAT64 64:ff9b::/96, SIIT ::ffff:0:/96
    if (/^(?:100::|64:ff9b::|::ffff:0:)/i.test(clean)) return true;
    // ULA fc00::/7 — bắt đầu bằng fc hoặc fd
    if (/^f[cd]/i.test(clean)) return true;
    // Link-local fe80::/10 — bắt đầu bằng fe8, fe9, fea, feb
    if (/^fe[89ab]/i.test(clean)) return true;
    // Multicast ff00::/8 — bắt đầu bằng ff
    if (/^ff/i.test(clean)) return true;
    // Documentation 2001:db8::/32
    if (/^2001:0?db8/i.test(clean)) return true;

    return false;
  }

  return true;
}

/**
 * Kiểm tra xem hostname có thuộc dải private / loopback / reserved hay không.
 */
export function isPrivateOrReservedHost(hostname: string): boolean {
  if (!hostname) return true;

  const host = hostname.toLowerCase().trim().replace(/\.+$/, "");
  if (!host) return true;

  // Loopback and well-known local names
  if (host === "localhost" || host === "0.0.0.0") return true;

  // Bare hostname with no dot = intranet (e.g. "intranet", "myserver", "backend")
  if (!host.includes(".") && !host.startsWith("[")) return true;

  // .local / .internal / .localhost / .lan TLD
  if (/\.(local|internal|localhost|lan)$/.test(host)) return true;

  // Nếu hostname là IP trực tiếp (IPv4 hoặc IPv6)
  const isIp =
    /^\d+\.\d+\.\d+\.\d+$/.test(host) ||
    host.includes(":") ||
    (host.startsWith("[") && host.endsWith("]"));
  if (isIp) {
    return isPrivateOrReservedIp(host);
  }

  return false;
}

export interface IsPublicHttpUrlOptions {
  /**
   * Nếu `true`, bỏ qua kiểm tra private IP / loopback.
   * Mặc định: `process.env.NODE_ENV !== 'production'`
   * (tức là tự động cho phép private URL trong môi trường dev/test).
   */
  allowPrivate?: boolean;
}

export interface SafeEvidenceUrlOptions extends SafeRedirectOptions {
  /** Endpoint MinIO nội bộ được cấu hình (vd: http://ppe-minio:9000 hoặc http://localhost:9000). */
  minioEndpoint?: string;
  /** Bucket chứa ảnh bằng chứng được phép truy cập (mặc định ppe-evidences). */
  bucketName?: string;
}

const INTERNAL_EVIDENCE_DOWNLOAD_PATH_REGEX =
  /^\/api\/v1\/(?:incidents\/evidences|evidences)\/[A-Za-z0-9_-]{8,128}\/download$/;

/**
 * Kiểm tra đường dẫn tương đối tới API tải bằng chứng nội bộ của chính Gateway/Incident Service.
 * Không chứa host, query string hay path traversal (`..`, `//`) nên hoàn toàn miễn nhiễm SSRF.
 */
export function isSafeInternalEvidencePath(urlString: string): boolean {
  if (!urlString || typeof urlString !== "string") return false;
  const trimmed = urlString.trim();
  if (!trimmed.startsWith("/") || trimmed.startsWith("//")) return false;
  if (trimmed.includes("..") || trimmed.includes("\\")) return false;
  return INTERNAL_EVIDENCE_DOWNLOAD_PATH_REGEX.test(trimmed);
}

/**
 * Kiểm tra URL trỏ chính xác về MinIO endpoint & bucket chứa ảnh bằng chứng đã cấu hình.
 */
export function isTrustedMinioEvidenceUrl(
  urlString: string,
  minioEndpoint?: string,
  bucketName?: string,
): boolean {
  if (!urlString || !minioEndpoint || !bucketName) return false;
  try {
    const target = new URL(urlString);
    const trustedBase = new URL(minioEndpoint);
    if (!["http:", "https:"].includes(target.protocol)) return false;
    if (target.origin !== trustedBase.origin) return false;
    const cleanBucket = bucketName.replace(/^\/+|\/+$/g, "");
    if (!cleanBucket) return false;
    if (target.pathname.includes("..")) return false;
    return target.pathname.startsWith(`/${cleanBucket}/`);
  } catch {
    return false;
  }
}

/**
 * Kiểm tra hợp lệ URL bằng chứng PPE (tương đối nội bộ, MinIO đã cấu hình hoặc Public HTTP/HTTPS URL).
 */
export function isSafeEvidenceUrl(
  urlString: string,
  options: SafeEvidenceUrlOptions = {},
): boolean {
  if (!urlString || typeof urlString !== "string") return false;
  if (isSafeInternalEvidencePath(urlString)) return true;
  if (
    isTrustedMinioEvidenceUrl(
      urlString,
      options.minioEndpoint,
      options.bucketName,
    )
  ) {
    return true;
  }
  return isPublicHttpUrl(urlString, options);
}

/**
 * Kiểm tra URL có phải là public HTTP/HTTPS URL hợp lệ (Static Syntax Check).
 */
export function isPublicHttpUrl(
  urlString: string,
  options: IsPublicHttpUrlOptions = {},
): boolean {
  if (!urlString || typeof urlString !== "string") return false;
  try {
    const parsed = new URL(urlString);
    if (!["http:", "https:"].includes(parsed.protocol)) return false;
    if (parsed.username || parsed.password) return false;

    const allowPrivate =
      options.allowPrivate ?? process.env.NODE_ENV !== "production";
    if (allowPrivate) return true;

    return !isPrivateOrReservedHost(parsed.hostname);
  } catch {
    return false;
  }
}

/**
 * Kiểm tra URL có scheme http/https hợp lệ (backward-compatible, không chặn private IP).
 */
export function isValidHttpUrl(urlString: string): boolean {
  try {
    const parsed = new URL(urlString);
    return ["http:", "https:"].includes(parsed.protocol);
  } catch {
    return false;
  }
}

/**
 * Trích xuất hostname từ URL. Trả về chuỗi rỗng nếu URL không hợp lệ.
 */
export function extractDomain(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    return "";
  }
}

export interface DnsValidationOptions {
  /**
   * Cho phép IP private (dùng cho môi trường development / unit test)
   */
  allowPrivate?: boolean;
  /**
   * Mock resolver phục vụ kiểm thử unit test độc lập
   */
  dnsLookup?: (
    hostname: string,
    options: { all: boolean },
  ) => Promise<Array<{ address: string; family: number }>>;
}

export interface DnsValidationResult {
  isValid: boolean;
  ips: string[];
  reason?: string;
}

/**
 * Phân giải toàn bộ bản ghi DNS (IPv4 & IPv6) của domain và xác minh không có IP nào trỏ về Private/Loopback/Metadata IP.
 * Chống kỹ thuật tấn công DNS Rebinding / Public domain trỏ về IP nội bộ.
 */
export async function resolveAndValidateDns(
  hostname: string,
  options: DnsValidationOptions = {},
): Promise<DnsValidationResult> {
  const allowPrivate = options.allowPrivate ?? false;

  // 1. Nếu hostname là cú pháp IP thô hoặc localhost
  if (isPrivateOrReservedHost(hostname)) {
    if (allowPrivate) {
      return { isValid: true, ips: [hostname] };
    }
    return {
      isValid: false,
      ips: [hostname],
      reason: `Hostname '${hostname}' is a private, loopback, or reserved address`,
    };
  }

  // 2. Thực hiện DNS resolution lấy tất cả A và AAAA records
  try {
    const lookupFn =
      options.dnsLookup ?? ((host, opts) => dns.promises.lookup(host, opts));
    const rawRecords = await lookupFn(hostname, { all: true });
    const records: Array<{ address: string; family?: number }> = Array.isArray(
      rawRecords,
    )
      ? rawRecords
      : rawRecords
        ? [rawRecords]
        : [];

    if (records.length === 0) {
      return {
        isValid: false,
        ips: [],
        reason: `No DNS records found for host '${hostname}'`,
      };
    }

    const ips = records.map(
      (r: { address: string; family?: number }) => r.address,
    );

    // 3. Kiểm tra từng IP đã phân giải được
    for (const ip of ips) {
      if (isPrivateOrReservedIp(ip)) {
        if (!allowPrivate) {
          return {
            isValid: false,
            ips,
            reason: `Host '${hostname}' resolved to private/reserved IP: ${ip}`,
          };
        }
      }
    }

    return { isValid: true, ips };
  } catch (error: any) {
    return {
      isValid: false,
      ips: [],
      reason: `DNS resolution failed for '${hostname}': ${error?.message || "Lookup error"}`,
    };
  }
}

export interface SafeRedirectOptions extends DnsValidationOptions {
  /**
   * Số lần chuyển hướng (redirect) tối đa được phép. Mặc định: 5
   */
  maxRedirects?: number;
  /**
   * Thời gian chờ tối đa (ms). Mặc định: 5000ms
   */
  timeoutMs?: number;
  /**
   * Custom HTTP fetcher phục vụ kiểm thử unit test giả lập HTTP redirect
   */
  httpFetcher?: (url: string) => Promise<{
    status: number;
    headers: Record<string, string | string[] | undefined>;
  }>;
}

export interface SafeRedirectResult {
  isValid: boolean;
  initialUrl: string;
  finalUrl: string;
  redirectCount: number;
  redirectChain: string[];
  ips: string[];
  reason?: string;
}

async function sendPinnedHeadRequest(
  targetUrl: URL,
  pinnedIp: string | undefined,
  timeoutMs: number,
): Promise<{ status: number; locationHeader?: string }> {
  const isHttps = targetUrl.protocol === "https:";
  const transport = isHttps ? https : http;
  const cleanPinned = pinnedIp
    ? pinnedIp.replace(/^\[|\]$/g, "")
    : "";
  const ipFamily = cleanPinned ? net.isIP(cleanPinned) : 0;

  const pinnedLookup =
    ipFamily === 4 || ipFamily === 6
      ? (
          _hostname: string,
          opts: any,
          cb?: (
            err: NodeJS.ErrnoException | null,
            address: any,
            family?: number,
          ) => void,
        ) => {
          const callback = typeof opts === "function" ? opts : cb;
          if (!callback) return;
          if (opts && typeof opts === "object" && opts.all) {
            callback(null, [{ address: cleanPinned, family: ipFamily }]);
            return;
          }
          callback(null, cleanPinned, ipFamily);
        }
      : undefined;

  return new Promise((resolve, reject) => {
    const req = transport.request(
      {
        protocol: targetUrl.protocol,
        hostname: targetUrl.hostname.replace(/^\[|\]$/g, ""),
        port: targetUrl.port || (isHttps ? 443 : 80),
        path: `${targetUrl.pathname}${targetUrl.search}`,
        method: "HEAD",
        ...(pinnedLookup ? { lookup: pinnedLookup as any } : {}),
        ...(isHttps ? { servername: targetUrl.hostname } : {}),
      },
      (res) => {
        res.resume();
        const loc = res.headers.location;
        resolve({
          status: res.statusCode ?? 0,
          locationHeader: Array.isArray(loc) ? loc[0] : loc,
        });
      },
    );

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Request timed out after ${timeoutMs}ms`));
    });
    req.on("error", (err) => reject(err));
    req.end();
  });
}

/**
 * Kiểm tra an toàn toàn diện chuỗi URL và các bước chuyển hướng HTTP Redirect.
 *
 * Quy trình:
 * 1. Validate cú pháp URL ban đầu và resolve DNS
 * 2. Theo dõi các HTTP 301/302/303/307/308 redirect từng bước
 * 3. Tại MỖI bước redirect:
 *    - Xác thực scheme phải là http: hoặc https: (chặn redirect sang file:, ftp:, gopher:, javascript:, data:)
 *    - Kiểm tra hostname đích
 *    - Phân giải DNS của hostname đích và kiểm tra tất cả IP
 *    - Phát hiện redirect vòng lặp vô tận (cycle detection)
 * 4. Trả về kết quả an toàn và URL cuối cùng
 */
export async function resolveSafeRedirectChain(
  urlString: string,
  options: SafeRedirectOptions = {},
): Promise<SafeRedirectResult> {
  const maxRedirects = options.maxRedirects ?? 5;
  const timeoutMs = options.timeoutMs ?? 5000;
  const redirectChain: string[] = [urlString];
  let currentUrl = urlString;
  let redirectCount = 0;
  let allIps: string[] = [];

  const visitedUrls = new Set<string>();

  while (redirectCount <= maxRedirects) {
    // A. Parse URL
    let parsed: URL;
    try {
      parsed = new URL(currentUrl);
    } catch {
      return {
        isValid: false,
        initialUrl: urlString,
        finalUrl: currentUrl,
        redirectCount,
        redirectChain,
        ips: allIps,
        reason: `Invalid URL format: '${currentUrl}'`,
      };
    }

    // B. Kiểm tra Protocol
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return {
        isValid: false,
        initialUrl: urlString,
        finalUrl: currentUrl,
        redirectCount,
        redirectChain,
        ips: allIps,
        reason: `Disallowed protocol '${parsed.protocol}'. Only http: and https: are permitted.`,
      };
    }

    // C. Chống Redirect Loop
    if (visitedUrls.has(currentUrl)) {
      return {
        isValid: false,
        initialUrl: urlString,
        finalUrl: currentUrl,
        redirectCount,
        redirectChain,
        ips: allIps,
        reason: `Circular redirect loop detected at '${currentUrl}'`,
      };
    }
    visitedUrls.add(currentUrl);

    // D. Phân giải DNS & kiểm tra Private IP ở bước hiện tại
    const dnsResult = await resolveAndValidateDns(parsed.hostname, options);
    allIps = Array.from(new Set([...allIps, ...dnsResult.ips]));

    if (!dnsResult.isValid) {
      return {
        isValid: false,
        initialUrl: urlString,
        finalUrl: currentUrl,
        redirectCount,
        redirectChain,
        ips: allIps,
        reason: dnsResult.reason,
      };
    }

    // E. Thực hiện request HEAD / GET không follow redirect tự động
    let status: number;
    let locationHeader: string | undefined;

    try {
      if (options.httpFetcher) {
        const res = await options.httpFetcher(currentUrl);
        status = res.status;
        const loc = res.headers["location"] || res.headers["Location"];
        locationHeader = Array.isArray(loc) ? loc[0] : loc;
      } else {
        const res = await sendPinnedHeadRequest(
          parsed,
          dnsResult.ips[0],
          timeoutMs,
        );
        status = res.status;
        locationHeader = res.locationHeader;
      }
    } catch (err: any) {
      return {
        isValid: false,
        initialUrl: urlString,
        finalUrl: currentUrl,
        redirectCount,
        redirectChain,
        ips: allIps,
        reason: `Network fetch failed at '${currentUrl}': ${err?.message || "Request error"}`,
      };
    }

    // F. Kiểm tra xem có Redirect không
    const isRedirect = [301, 302, 303, 307, 308].includes(status);

    if (!isRedirect || !locationHeader) {
      // Đã tới URL cuối cùng hợp lệ
      return {
        isValid: true,
        initialUrl: urlString,
        finalUrl: currentUrl,
        redirectCount,
        redirectChain,
        ips: allIps,
      };
    }

    // G. Chuyển sang URL chuyển hướng mới
    redirectCount++;
    if (redirectCount > maxRedirects) {
      return {
        isValid: false,
        initialUrl: urlString,
        finalUrl: currentUrl,
        redirectCount,
        redirectChain,
        ips: allIps,
        reason: `Maximum redirect limit (${maxRedirects}) exceeded`,
      };
    }

    try {
      // Hỗ trợ cả absolute URL và relative URL (e.g. "/path/to/target")
      const resolvedLocation = new URL(locationHeader, currentUrl).toString();
      redirectChain.push(resolvedLocation);
      currentUrl = resolvedLocation;
    } catch {
      return {
        isValid: false,
        initialUrl: urlString,
        finalUrl: currentUrl,
        redirectCount,
        redirectChain,
        ips: allIps,
        reason: `Invalid redirect Location header '${locationHeader}'`,
      };
    }
  }

  return {
    isValid: false,
    initialUrl: urlString,
    finalUrl: currentUrl,
    redirectCount,
    redirectChain,
    ips: allIps,
    reason: `Maximum redirect limit (${maxRedirects}) exceeded`,
  };
}

/**
 * SEC-31: Xác thực URL an toàn chống tấn công SSRF:
 * 1. Kiểm tra cú pháp tĩnh (isPublicHttpUrl)
 * 2. Phân giải DNS tại runtime (resolveAndValidateDns) chống DNS Rebinding
 * 3. Kiểm tra chuỗi redirect HTTP 30x (resolveSafeRedirectChain) chống redirect về IP nội bộ / Cloud Metadata
 */
export async function assertSafePublicUrl(
  urlStr: string,
  options: SafeRedirectOptions = {},
): Promise<void> {
  if (!urlStr || typeof urlStr !== "string") {
    throw new AppError("URL không hợp lệ hoặc bị trống", 400, ERROR_CODE.VALIDATION_ERROR);
  }

  const allowPrivate = options.allowPrivate ?? false;

  if (!isPublicHttpUrl(urlStr, { allowPrivate })) {
    throw new AppError(
      "URL không hợp lệ hoặc trỏ về địa chỉ IP nội bộ bị chặn (SSRF)",
      400,
      ERROR_CODE.VALIDATION_ERROR,
    );
  }

  if (!allowPrivate) {
    const result = await resolveSafeRedirectChain(urlStr, options);
    if (!result.isValid) {
      throw new AppError(
        `Phát hiện rủi ro SSRF: ${result.reason || "Địa chỉ đích không phải IP công khai an toàn"}`,
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }
  }
}

/**
 * SEC-31 (PPE Evidence Extension):
 * Cho phép đường dẫn tải ảnh nội bộ (`/api/v1/incidents/evidences/:id/download`) và URL MinIO đã whitelist,
 * đồng thời giữ nguyên toàn bộ hàng rào SSRF & DNS Rebinding với mọi URL ngoài phạm vi tin cậy.
 */
export async function assertSafeEvidenceUrl(
  urlStr: string,
  options: SafeEvidenceUrlOptions = {},
): Promise<void> {
  if (!urlStr || typeof urlStr !== "string") {
    throw new AppError("URL không hợp lệ hoặc bị trống", 400, ERROR_CODE.VALIDATION_ERROR);
  }
  if (isSafeInternalEvidencePath(urlStr)) {
    return;
  }
  if (
    isTrustedMinioEvidenceUrl(
      urlStr,
      options.minioEndpoint,
      options.bucketName,
    )
  ) {
    return;
  }
  await assertSafePublicUrl(urlStr, options);
}

