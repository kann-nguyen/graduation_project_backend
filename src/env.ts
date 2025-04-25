import { z } from "zod";
import { threatMatchesVul } from "./controllers/artifact.controller";

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

/**
 * Xử lý từng threat hiện có trong artifact.threatList:
 * - Nếu có vulnerability tương ứng trong tempVuls thì cập nhật ticket thành "Processing".
 * - Nếu không có thì cập nhật ticket thành "Resolved" và xóa threat khỏi DB cũng như khỏi artifact.
 */
export async function processExistingThreats(artifact: any): Promise<void> {
  // Đảm bảo threatList đã được populate
  await artifact.populate("threatList");

  // Lưu danh sách threatId cần loại bỏ sau này
  const threatsToRemove: any[] = [];

  for (const threat of artifact.threatList) {
    // Kiểm tra có tồn tại vulnerability tương ứng trong tempVuls
    const existsInTemp = artifact.tempVuls?.some((vuln: any) => threatMatchesVul(threat, vuln));

    if (existsInTemp) {
      // Cập nhật trạng thái ticket của threat thành "Processing"
      await updateTicketStatusForThreat(threat._id, false);
    } else {
      // Cập nhật trạng thái ticket của threat thành "Resolved"
      await updateTicketStatusForThreat(threat._id, true);

      // Đánh dấu threat này để xóa
      threatsToRemove.push(threat._id);
      console.log(`Threat ${threat._id} bị xóa vì không tìm thấy vulnerability tương ứng.`);
    }
  }

  // Loại bỏ các threat đã bị xóa khỏi artifact.threatList
  artifact.threatList = artifact.threatList.filter(
    (t: any) => !threatsToRemove.includes(t._id.toString())
  );
}
