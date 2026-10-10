export const maintenanceCacheService = {
  async getConfig() {
    return {
      enabled: false,
      status: "ONLINE",
    };
  },
};
