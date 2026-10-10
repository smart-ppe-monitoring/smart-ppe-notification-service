# smart-ppe-notification-service

> **Notification & Realtime SSE Microservice** cho Hệ thống Giám sát An toàn Lao động Thông minh (**Smart PPE Monitoring System**), phụ trách phân luồng cảnh báo đa kênh (In-App SSE, Email Queue), cấp vé phát luồng bảo mật (`stream-ticket`), ma trận trọng số chống Alert Fatigue và đồng bộ sự kiện qua EventBus theo chuẩn **D08.pdf (Mục 3.5 & Task BE-08)**.

---

## 🏛️ Trách nhiệm nghiệp vụ

- **Đẩy cảnh báo thời gian thực Server-Sent Events (`/api/v1/notifications/stream`)**: Quản lý kết nối persistent HTTP stream tới Dashboard giám sát của Cán bộ an toàn với độ trễ < 1s.
- **Bắt tay SSE An toàn qua Stream Ticket (`/api/v1/notifications/stream-ticket`)**: Cấp vé tạm thời 60 giây chứa mục đích `SSE_STREAM_TICKET` để browser kết nối EventSource an toàn mà không làm lộ Access Token qua Query Param (CWE-532).
- **Ma trận trọng số độ nghiêm trọng (`SEVERITY_WEIGHT`)**: Lọc ngưỡng thông báo chống quá tải cảnh báo (Alert Fatigue) - SSE nhận từ mức `LOW`, Email/Webhook chỉ gửi khi mức `HIGH` hoặc `CRITICAL`.
- **Hàng đợi gửi Email phi tập trung (`EmailWorker`)**: Sử dụng khóa hàng nguyên tử `FOR UPDATE SKIP LOCKED` chống race condition gửi trùng email trong cụm multi-pod.

---

## 🚀 Khởi chạy cục bộ (Local Development)

```bash
# 1. Cài đặt dependencies
pnpm install

# 2. Cấu hình biến môi trường
cp .env.example .env

# 3. Sinh Prisma Client từ schema
pnpm run prisma:generate

# 4. Khởi chạy chế độ phát triển
pnpm run dev
# Server lắng nghe tại http://localhost:8894
```

---

## 🧪 Kiểm thử tự động (Unit Tests)

```bash
pnpm test
```

---

## 🐳 Triển khai Docker

```bash
docker build -t smart-ppe-notification-service .
docker run -p 8894:8894 --env-file .env smart-ppe-notification-service
```
