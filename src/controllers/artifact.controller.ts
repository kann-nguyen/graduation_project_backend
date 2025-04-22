import { isDocumentArray } from "@typegoose/typegoose";
import { Request, Response } from "express";
import { ArtifactModel, ChangeHistoryModel, ProjectModel, ThreatModel, TicketModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import { Artifact } from "../models/artifact";
import { Vulnerability } from "../models/vulnerability";
import { Threat } from "../models/threat";
import path from "path";
import * as fs from "fs/promises";
import { autoCreateTicketFromThreat } from "./ticket.controller";

// Lấy tất cả artifacts thuộc về một project cụ thể
export async function getAll(req: Request, res: Response) {
  const { projectName } = req.query;
  try {
    // Tìm project theo tên và populate danh sách phase cùng artifacts của nó
    const project = await ProjectModel.findOne({
      name: projectName,
    }).populate({
      path: "phaseList",
      populate: {
        path: "artifacts",
      },
    });
    
    // Nếu không tìm thấy project, trả về lỗi
    if (!project) {
      return res.json(errorResponse("Project not found"));
    }
    
    // Kiểm tra nếu phaseList là một mảng tài liệu hợp lệ
    if (isDocumentArray(project.phaseList)) {
      // Lấy tất cả artifacts từ các phase
      const artifacts = project.phaseList
        .map((phase) => phase.artifacts)
        .flat();
      
      // Trả về danh sách artifacts kèm theo thông báo thành công
      return res.json(
        successResponse(
          artifacts,
          "Get all artifacts with respective vulnerabilities"
        )
      );
    }
  } catch (error) {
    // Xử lý lỗi nếu có vấn đề trong quá trình lấy dữ liệu
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

// Lấy một artifact cụ thể dựa trên ID
export async function get(req: Request, res: Response) {
  const { id } = req.params;
  try {
    // Tìm artifact theo ID
    const artifact = await ArtifactModel.findById(id);
    
    // Trả về artifact nếu tìm thấy
    return res.json(successResponse(artifact, "Artifact fetched successfully"));
  } catch (error) {
    // Xử lý lỗi nếu có
    return res.json(error);
  }
}

// Cập nhật artifact với dữ liệu mới và danh sách threats
export async function update(req: Request, res: Response) {
  const { id } = req.params;
  const { data } = req.body;
  const { threatList } = data; // Danh sách tên các threat
  try {
    // Tìm danh sách các threat trong database dựa trên tên
    const threats = await ThreatModel.find({ name: { $in: threatList } });
    
    // Cập nhật artifact với dữ liệu mới và danh sách threats
    const artifact = await ArtifactModel.findByIdAndUpdate(
      id,
      {
        ...data,
        threatList: threats, // Gán danh sách threats vào artifact
      },
      {
        new: true, // Trả về artifact sau khi đã cập nhật
      }
    );
    
    // Trả về artifact sau khi cập nhật thành công
    return res.json(successResponse(artifact, "Artifact updated successfully"));
  } catch (error) {
    // Xử lý lỗi nếu có vấn đề trong quá trình cập nhật
    return res.json(error);
  }
}

/**
 * Từ artifact, sinh các threat dựa trên vulnerabilityList
 */
export async function generateAndAttachThreats1(req: Request, res: Response) {
  const artifactId = req.params.id;

  try {
    // Step 1: Fetch the artifact by ID
    const artifact = await ArtifactModel.findById(artifactId);
    if (!artifact) {
      return res.status(404).json({ message: `Artifact with ID ${artifactId} not found.`});
    }

    // Step 2: Check if there are any vulnerabilities associated with the artifact
    if (!artifact.vulnerabilityList || artifact.vulnerabilityList.length === 0) {
      return res.status(400).json({ message: `No vulnerabilities found for artifact ${artifact.name}.` });
    }

    console.log(`🚧 Generating threats for artifact: ${artifact.name}`);

    // Initialize threat list if not already present
    artifact.threatList = artifact.threatList || [];

    // Step 3: Loop through vulnerabilities and create threats
    for (const vuln of artifact.vulnerabilityList) {
      const threatData = createThreatFromVuln(vuln, artifact.type);

      // Create a new threat and save it to the database
      const newThreat = await ThreatModel.create({
        ...threatData,
      });

      // Step 4: Update artifact's threat list
      artifact.threatList.push(newThreat._id);
    }

    // Step 5: Save updated artifact with attached threats
    await artifact.save();

    // Respond with success
    console.log(`✅ Successfully saved ${artifact.threatList.length} threats for artifact "${artifact.name}"`);
    return res.status(200).json({
      message: `Successfully saved ${artifact.threatList.length} threats for artifact "${artifact.name}"`,
      threatList: artifact.threatList,
    });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "An error occurred while generating threats." });
  }
}

export async function generateAndAttachThreats(artifactId: any) {
  try {
    // Step 1: Fetch the artifact by ID
    const artifact = await ArtifactModel.findById(artifactId);
    if (!artifact) {
      return;
    }

    // Step 2: Check if there are any vulnerabilities associated with the artifact
    if (!artifact.vulnerabilityList || artifact.vulnerabilityList.length === 0) {
      return;
    }

    console.log(`🚧 Generating threats for artifact: ${artifact.name}`);

    // Initialize threat list if not already present
    artifact.threatList = artifact.threatList || [];

    // Step 3: Loop through vulnerabilities and create threats
    for (const vuln of artifact.vulnerabilityList) {
      const threatData = createThreatFromVuln(vuln, artifact.type);

      // Create a new threat and save it to the database
      const newThreat = await ThreatModel.create({
        ...threatData,
      });

      // Step 4: Update artifact's threat list
      artifact.threatList.push(newThreat._id);

      autoCreateTicketFromThreat(artifactId, newThreat._id);
    }

    // Step 5: Save updated artifact with attached threats
    await artifact.save();

    // Respond with success
    console.log(`✅ Successfully saved ${artifact.threatList.length} threats for artifact "${artifact.name}"`);

  } catch (error) {
    console.error(error);
    return;
  }
}

// Generate a threat from a vulnerability
function createThreatFromVuln(vuln: any, artifactType: string): Partial<Threat> {
  const votes = getVotes(vuln);
  const threatType = resolveThreatType(votes, artifactType);
  const baseScore = vuln.score || 0;
  return {
    name: vuln.cveId,
    description: vuln.description ?? "Have no des",
    type: threatType ?? "Spoofing",
    mitigation: ["Pending mitigation plan"],
    status: "Non mitigated",
    score: {
      total: baseScore,
      details: {
        damage: baseScore,
        reproducibility: baseScore,
        exploitability: baseScore,
        affectedUsers: baseScore,
        discoverability: baseScore,
      },
    },
  };
}

//////////////////////////
type ThreatType =
  | "Spoofing"
  | "Tampering"
  | "Repudiation"
  | "Information Disclosure"
  | "Denial of Service"
  | "Elevation of Privilege";

type VotingSource = "CWE" | "Keyword" | "Severity";

interface Vote {
  type: ThreatType;
  source: VotingSource;
  weight: number;
}

// Weighted vote rules
const sourceWeights: Record<VotingSource, number> = {
  CWE: 3,
  Keyword: 2,
  Severity: 1,
};

//https://www.researchgate.net/publication/351864310_Towards_Practical_Cybersecurity_Mapping_of_STRIDE_and_CWE_-_a_Multi-perspective_Approach
export async function loadCweMapping(): Promise<Record<string, Threat["type"]>> {
  try {
    // Resolve the path to the JSON file
    const filePath = path.resolve("src\\utils\\cweToThreat.json");
    // Read the file contents as a UTF-8 string
    const data = await fs.readFile(filePath, "utf8");
    // Parse the JSON content into an object
    const mapping: Record<string, Threat["type"]> = JSON.parse(data);
    return mapping;
  } catch (err) {
    console.error("Failed to load CWE mapping:", err);
    return {};
  }
}

let cweToStrideMap:any;

(async () => {
  cweToStrideMap = await loadCweMapping();
})();

// Collect all potential threat "votes" for a given vulnerability
export function getVotes(vuln: Vulnerability): Vote[] {
  const votes: Vote[] = [];

  // === (1) CWE Mapping ===
  for (const cwe of vuln.cwes || []) {
    const mappedType = cweToStrideMap[cwe] ?? "Spoofing";
    if (mappedType) {
      votes.push({
        type: mappedType as ThreatType,
        source: "CWE",
        weight: sourceWeights["CWE"],
      });
    } else {
    }
  }

  // === (2) Keyword Matching in Description ===
  const desc = vuln.description?.toLowerCase() || "have no des";

  if (/privilege|unauthorized/.test(desc)) {
    votes.push({ type: "Elevation of Privilege", source: "Keyword", weight: sourceWeights["Keyword"] });
  }

  if (/spoof|impersonation/.test(desc)) {
    votes.push({ type: "Spoofing", source: "Keyword", weight: sourceWeights["Keyword"] });
  }

  if (/denial|crash/.test(desc)) {
    votes.push({ type: "Denial of Service", source: "Keyword", weight: sourceWeights["Keyword"] });
  }

  if (/leak|plaintext/.test(desc)) {
    votes.push({ type: "Information Disclosure", source: "Keyword", weight: sourceWeights["Keyword"] });
  }

  // === (3) Severity-based Inference ===
  if (vuln.severity === "Critical") {
    votes.push({ type: "Elevation of Privilege", source: "Severity", weight: sourceWeights["Severity"] });
  } else if (vuln.severity === "High") {
    votes.push({ type: "Tampering", source: "Severity", weight: sourceWeights["Severity"] });
  }

  console.log("🗳️ Final Vote List:", votes);
  return votes;
}

// Determine the most likely threat type from the votes
export function resolveThreatType(votes: Vote[], artifactType: string): ThreatType | null {
  const invalidCombos: Record<string, ThreatType[]> = {
    docs: ["Tampering", "Elevation of Privilege"],
    log: ["Elevation of Privilege"],
  };

  // Remove votes that are not valid for the given artifact type
  const filteredVotes = votes.filter(
    (vote) => !invalidCombos[artifactType]?.includes(vote.type)
  );

  const scoreMap: Record<ThreatType, number> = {} as Record<ThreatType, number>;

  // Calculate scores
  for (const vote of filteredVotes) {
    scoreMap[vote.type] = (scoreMap[vote.type] || 0) + vote.weight;
  }

  // Sort threat types by their score descending
  const sorted = Object.entries(scoreMap).sort((a, b) => b[1] - a[1]);

  const result = sorted.length > 0 ? (sorted[0][0] as ThreatType) : null;

  return result;
}



/**
 * Kiểm tra threat có phù hợp với vulnerability không. 
 * Giả sử threat.name chứa định danh (ví dụ cveId) của vulnerability.
 */
function threatMatchesVul(threat: any, vuln: any): boolean {
  return threat.name === vuln.cveId;
}

/**
 * Cập nhật trạng thái của ticket liên quan đến threat.
 * Nếu shouldProcess = true: cập nhật ticket thành "Processing",
 * nếu không: cập nhật ticket thành "Resolved".
 */
async function updateTicketStatusForThreat(threatId: any, isDone: boolean) {
  // Tìm ticket có liên kết với threat này
  const ticket = await TicketModel.findOne({ targetedThreat: threatId });
  if (!ticket) {
    console.warn(`Không tìm thấy ticket liên kết với threat ${threatId}`);
    return;
  }
  if (ticket.status == "Submitted") {
    let newStatus = isDone ? "Resolved" : "Processing";

    await TicketModel.findByIdAndUpdate(ticket._id, { $set: { status: newStatus } });

    // Ghi lại lịch sử thay đổi
    await ChangeHistoryModel.create({
      objectId: ticket._id,
      action: "update",
      timestamp: ticket.createdAt,
      account: ticket.assigner?._id,
      description: `Ticket ${ticket.title} được cập nhật thành ${newStatus}`,
    });
  }
  
}

/**
 * Xử lý từng threat hiện có trong artifact.threatList:
 * - Nếu có vulnerability tương ứng trong tempVuls thì cập nhật ticket thành "Processing".
 * - Nếu không có thì cập nhật ticket thành "Resolved" và xóa threat khỏi DB cũng như khỏi artifact.
 */
async function processExistingThreats(artifact: any): Promise<void> {
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

/**
 * Xử lý danh sách vulnerability mới từ artifact.tempVuls:
 * Với mỗi vulnerability trong tempVuls, nếu nó không có trong artifact.vulnerabilityList,
 * thì tạo threat mới và thêm vào artifact.threatList.
 */
async function processNewVulnerabilities(artifact: any): Promise<void> {
  for (const newVul of artifact.tempVuls || []) {
    // Kiểm tra nếu vulnerability này chưa tồn tại trong artifact.vulnerabilityList
    const exists = artifact.vulnerabilityList?.some(
      (oldVul: any) => oldVul.cveId === newVul.cveId
    );
    if (!exists) {
      const threatData = createThreatFromVuln(newVul, artifact.type);
      const createdThreat = await ThreatModel.create(threatData);
      artifact.threatList.push(createdThreat._id);
      console.log(`Threat mới được tạo cho vulnerability ${newVul.cveId}`);
    }
  }
}

/**
 * Hàm cập nhật artifact sau khi scan:
 * 1. Xử lý threat hiện có
 * 2. Xử lý các vulnerability mới (tempVuls)
 * 3. Cập nhật artifact.vulnerabilityList từ tempVuls và lưu artifact.
 */
export async function updateArtifactAfterScan(artifact: any): Promise<void> {
  try {
    // 1. Xử lý threat hiện có trong artifact
    await processExistingThreats(artifact);

    // 2. Xử lý tempVuls: tạo threat mới cho vulnerability không có trong danh sách cũ
    await processNewVulnerabilities(artifact);

    // 3. Gán lại vulnerabilityList bằng tempVuls và lưu artifact
    artifact.vulnerabilityList = artifact.tempVuls || [];
    await artifact.save();
    console.log(`Artifact ${artifact._id} đã được cập nhật với vulnerabilityList mới từ tempVuls.`);
  } catch (error) {
    console.error("Lỗi khi cập nhật artifact sau scan:", error);
    throw error;
  }
}



