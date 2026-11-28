export interface ZaloBotBindingDto {
  id: string;
  userId: string;
  chatIdMasked: string;
  chatType: "PRIVATE" | "GROUP" | string;
  displayName: string | null;
  linkedAt: Date;
  updatedAt: Date;
}

export interface ZaloBotStatusDto {
  botConfigured: boolean;
  botMode: "disabled" | "polling" | "webhook";
  botAccountName: string | null;
  canJoinGroups: boolean;
  linked: boolean;
  binding: ZaloBotBindingDto | null;
}

export interface ZaloLinkTokenResponseDto {
  code: string;
  command: string;
  expiresAt: Date;
  expiresInSeconds: number;
  botAccountName: string | null;
  botConfigured: boolean;
}

export interface SetZaloWebhookDto {
  url: string;
}

export interface SendZaloTestDto {
  message?: string;
}
