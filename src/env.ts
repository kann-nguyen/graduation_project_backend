import { z } from "zod";

export const envVariables = z.object({
  MONGO_URL: z.string(),
  REDIS_URL: z.string(),
  CLIENT_URL: z.string(),
  SERVER_URL: z.string(),
  SESSION_SECRET: z.string(),
  GITHUB_CLIENT_ID: z.string(),
  GITHUB_CLIENT_SECRET: z.string(),
  GITLAB_CLIENT_ID: z.string(),
  GITLAB_CLIENT_SECRET: z.string(),
  IMAGE_SCANNING_URL: z.string(),
});

declare global {
  namespace NodeJS {
    interface ProcessEnv extends z.infer<typeof envVariables> {}
  }
}
