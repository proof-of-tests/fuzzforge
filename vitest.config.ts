import { defineWorkersConfig, readD1Migrations } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig(async () => {
  const migrations = await readD1Migrations("worker/migrations");

  return {
    test: {
      poolOptions: {
        workers: {
          wrangler: { configPath: "wrangler.toml" },
          miniflare: {
            bindings: { TEST_MIGRATIONS: migrations },
          },
        },
      },
      setupFiles: ["worker/test/apply-migrations.ts"],
    },
  };
});
