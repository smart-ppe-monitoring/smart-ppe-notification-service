import {
  notificationPrisma,
  DEFAULT_NOTIFICATION_TRANSACTION_OPTIONS,
} from "../../database/notification.client";

export interface UserZaloBindingRecord {
  id: string;
  userId: string;
  chatId: string;
  chatType: string;
  zaloUserId: string | null;
  displayName: string | null;
  linkedAt: Date;
  updatedAt: Date;
}

export class ZaloBotRepository {
  private readonly db = notificationPrisma;

  async findBindingByUserId(
    userId: string,
  ): Promise<UserZaloBindingRecord | null> {
    return this.db.userZaloBinding.findUnique({
      where: { userId },
    });
  }

  async findBindingsByUserIds(
    userIds: string[],
  ): Promise<UserZaloBindingRecord[]> {
    if (userIds.length === 0) return [];
    return this.db.userZaloBinding.findMany({
      where: { userId: { in: userIds } },
    });
  }

  async findBindingByChatId(
    chatId: string,
  ): Promise<UserZaloBindingRecord | null> {
    return this.db.userZaloBinding.findUnique({
      where: { chatId },
    });
  }

  async upsertBinding(data: {
    userId: string;
    chatId: string;
    chatType: string;
    zaloUserId?: string | null;
    displayName?: string | null;
  }): Promise<UserZaloBindingRecord> {
    return this.db.$transaction(async (tx) => {
      // Nếu chatId này từng gắn với tài khoản khác, gỡ liên kết cũ để tránh xung đột unique(chat_id)
      await tx.userZaloBinding.deleteMany({
        where: {
          chatId: data.chatId,
          userId: { not: data.userId },
        },
      });

      return tx.userZaloBinding.upsert({
        where: { userId: data.userId },
        create: {
          userId: data.userId,
          chatId: data.chatId,
          chatType: data.chatType,
          zaloUserId: data.zaloUserId || null,
          displayName: data.displayName || null,
        },
        update: {
          chatId: data.chatId,
          chatType: data.chatType,
          zaloUserId: data.zaloUserId || null,
          displayName: data.displayName || null,
          linkedAt: new Date(),
        },
      });
    }, DEFAULT_NOTIFICATION_TRANSACTION_OPTIONS);
  }

  async deleteBindingByUserId(userId: string): Promise<number> {
    const res = await this.db.userZaloBinding.deleteMany({
      where: { userId },
    });
    return res.count;
  }

  async deleteBindingByChatId(chatId: string): Promise<number> {
    const res = await this.db.userZaloBinding.deleteMany({
      where: { chatId },
    });
    return res.count;
  }

  async createLinkToken(
    userId: string,
    codeHash: string,
    expiresAt: Date,
  ): Promise<void> {
    await this.db.$transaction(async (tx) => {
      await tx.zaloLinkToken.deleteMany({
        where: {
          userId,
          usedAt: null,
        },
      });

      await tx.zaloLinkToken.create({
        data: {
          userId,
          codeHash,
          expiresAt,
        },
      });
    }, DEFAULT_NOTIFICATION_TRANSACTION_OPTIONS);
  }

  /**
   * Tiêu thụ mã liên kết 1 lần (single-use) an toàn chống race condition.
   */
  async consumeLinkToken(codeHash: string): Promise<{ userId: string } | null> {
    return this.db.$transaction(async (tx) => {
      const now = new Date();
      const token = await tx.zaloLinkToken.findFirst({
        where: {
          codeHash,
          usedAt: null,
          expiresAt: { gt: now },
        },
      });

      if (!token) {
        return null;
      }

      const claimed = await tx.zaloLinkToken.updateMany({
        where: {
          id: token.id,
          usedAt: null,
        },
        data: {
          usedAt: now,
        },
      });

      if (claimed.count !== 1) {
        return null;
      }

      return { userId: token.userId };
    }, DEFAULT_NOTIFICATION_TRANSACTION_OPTIONS);
  }
}

export const zaloBotRepository = new ZaloBotRepository();
