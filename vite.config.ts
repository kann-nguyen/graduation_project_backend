import { defineConfig } from "vitest/config";
import * as path from "path";
// https://vitejs.dev/config/
export default defineConfig({
  resolve: {
    alias: {
      "~": path.resolve(__dirname, "src"),
    },
  },
});
