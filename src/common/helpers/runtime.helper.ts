/**
 * Kiểm tra tiến trình hiện tại có đang chạy trong môi trường automated test (NODE_ENV=test hoặc node --test) hay không.
 */
export function isAutomatedTestRuntime(): boolean {
  return (
    process.env.NODE_ENV === "test" ||
    Boolean(process.env.NODE_TEST_CONTEXT)
  );
}
