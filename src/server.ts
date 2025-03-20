import * as dotenv from "dotenv";
dotenv.config();
import mongoose from "mongoose";
import app from "./app";
import redis from "./redis"; // Already initialized, no need to call .connect()

const port = process.env.PORT || 3001;

if (!process.env.MONGO_URL) {
  throw new Error("MONGO_URL must be defined");
}

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URL)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB Error:", err));

// No need to call redis.connect() again! It's handled inside redis.ts
app.listen(port, () => console.log(`🚀 Server running on port ${port}`));

// Handle app termination to close Redis properly
process.on("SIGINT", async () => {
  console.log("🔴 Closing Redis connection...");
  await redis.quit();
  process.exit(0);
});
