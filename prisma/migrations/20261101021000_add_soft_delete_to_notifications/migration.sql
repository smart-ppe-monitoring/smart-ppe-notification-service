-- AlterTable
ALTER TABLE "notifications" ADD COLUMN "deleted_at" TIMESTAMP(3);

-- CreateIndex
CREATE INDEX "notifications_deleted_at_idx" ON "notifications"("deleted_at");

-- DropForeignKey
ALTER TABLE "notification_logs" DROP CONSTRAINT IF EXISTS "notification_logs_notification_id_fkey";

-- AddForeignKey with RESTRICT
ALTER TABLE "notification_logs" ADD CONSTRAINT "notification_logs_notification_id_fkey" FOREIGN KEY ("notification_id") REFERENCES "notifications"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
