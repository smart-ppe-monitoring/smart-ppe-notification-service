-- AlterTable
ALTER TABLE "notifications" ADD COLUMN "archived_at" TIMESTAMP(3);

-- CreateIndex
CREATE INDEX "notifications_user_id_archived_at_idx" ON "notifications"("user_id", "archived_at");

-- CreateIndex
CREATE INDEX "email_notifications_created_at_idx" ON "email_notifications"("created_at");
