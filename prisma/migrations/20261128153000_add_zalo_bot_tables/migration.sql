-- CreateTable
CREATE TABLE "user_zalo_bindings" (
    "id" UUID NOT NULL DEFAULT uuid_generate_v7(),
    "user_id" UUID NOT NULL,
    "chat_id" VARCHAR(128) NOT NULL,
    "chat_type" VARCHAR(20) NOT NULL DEFAULT 'PRIVATE',
    "zalo_user_id" VARCHAR(128),
    "display_name" VARCHAR(150),
    "linked_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "user_zalo_bindings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "zalo_link_tokens" (
    "id" UUID NOT NULL DEFAULT uuid_generate_v7(),
    "user_id" UUID NOT NULL,
    "code_hash" VARCHAR(64) NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "used_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "zalo_link_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "user_zalo_bindings_user_id_key" ON "user_zalo_bindings"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "user_zalo_bindings_chat_id_key" ON "user_zalo_bindings"("chat_id");

-- CreateIndex
CREATE UNIQUE INDEX "zalo_link_tokens_code_hash_key" ON "zalo_link_tokens"("code_hash");

-- CreateIndex
CREATE INDEX "zalo_link_tokens_user_id_expires_at_idx" ON "zalo_link_tokens"("user_id", "expires_at");
