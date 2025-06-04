import { isDocumentArray } from "@typegoose/typegoose";
import { Request, Response } from "express";
import { ArtifactModel, ProjectModel, ThreatModel, PhaseModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import { Vulnerability } from "../models/vulnerability";
import { Threat } from "../models/threat";
import path from "path";
import * as fs from "fs/promises";
import { autoCreateTicketFromThreat, updateTicketStatusForThreat } from "./ticket.controller";
import { calculateScoresFromVulnerability } from "./threat.controller";
import { validateArtifact } from "../utils/validateArtifact";
import { scanArtifact } from "./phase.controller";

// Lấy tất cả artifacts thuộc về một project cụ thể
export async function getAll(req: Request, res: Response) {
  const { projectName } = req.query;
  try {    // Tìm project theo tên và populate danh sách phase cùng artifacts của nó
    const project = await ProjectModel.findOne({
      name: projectName,
    }).populate({
      path: "phaseList",
      populate: {
        path: "artifacts"// Explicitly include isScanning and state fields
      },
    });

    // Nếu không tìm thấy project, trả về lỗi
    if (!project) {
      return res.json(errorResponse("Project not found"));
    }

    // Kiểm tra nếu phaseList là một mảng tài liệu hợp lệ
    if (isDocumentArray(project.phaseList)) {      // Lấy tất cả artifacts từ các phase
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
  console.log(data);

  // Validate artifact before proceeding
  const validationResult = await validateArtifact(data);
  
  // Set the state based on validation result
  data.state = validationResult.valid ? "valid" : "invalid";

  try {
    // Cập nhật artifact với dữ liệu mới
    const artifact = await ArtifactModel.findByIdAndUpdate(
      id,
      {
        ...data,
      },
      {
        new: true, // Trả về artifact sau khi đã cập nhật
      }
    );

    if (!artifact) {
      return res.json(errorResponse("Artifact not found"));
    }

    // Find the phase that contains this artifact
    const phase = await PhaseModel.findOne({ artifacts: artifact._id });
    
    if (!phase) {
      return res.json(errorResponse("Phase containing this artifact not found"));
    }

    // ✅ Bắt đầu scan ở background only if artifact is valid
    if (artifact.state === "valid") {
      res.json(successResponse(null, "Artifact updated successfully and scanning started in background"));
      setImmediate(async () => {
        try {
          await scanArtifact(artifact, phase._id.toString());
        } catch (error) {
          console.error("[ERROR] Scanning failed:", error);
        }
      });
    } else {
      res.json(successResponse(null, `Artifact updated successfully but is not valid: ${validationResult.error}`));
    }

  } catch (error) {
    console.error("[ERROR] Internal server error", error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function updateRateScan(req: Request, res: Response) {
  const { id } = req.params;
  const { data } = req.body;
  const { rate } = data;

  //check xem role có phải manager không
  const user = req.user;
  if (!user || user.role !== "project_manager") {
    return res.json(errorResponse("You are not authorized to update this artifact"));
  }

  try {
    if (rate < 0 || rate > 100) {
      return res.json(errorResponse("Rate must be between 0 and 100"));
    }

    // Cập nhật artifact với dữ liệu mới và danh sách threats
    const artifact = await ArtifactModel.findByIdAndUpdate(
      id,
      {
        rateReScan: rate// Gán danh sách threats vào artifact
      },
      {
        new: true, // Trả về artifact sau khi đã cập nhật
      }
    );

    // Trả về artifact sau khi cập nhật thành công
    return res.json(successResponse(artifact, "Rate re-scan updated successfully"));
  } catch (error) {
    // Xử lý lỗi nếu có vấn đề trong quá trình cập nhật
    return res.json(error);
  }
}

// Generate a threat from a vulnerability
function createThreatFromVuln(vuln: any, artifactType: string): Partial<Threat> {
  const votes = getVotes(vuln);
  const threatType = resolveThreatType(votes, artifactType);

  // Calculate initial scores based on vulnerability data
  let scoreData;
  try {
    // Import the calculation function from threatModeling.controller
    scoreData = calculateScoresFromVulnerability(vuln);
  } catch (error) {
    console.error("Error calculating initial threat scores:", error);
    // Fallback to default scores if the calculation fails
    scoreData = {
      total: vuln.score ? vuln.score / 2 : 2.5, // Convert CVSS (0-10) to our scale (0-5)
      details: {
        damage: 2.5,
        reproducibility: 2.5,
        exploitability: 2.5,
        affectedUsers: 2.5,
        discoverability: 2.5,
      }
    };
  }

  return {
    name: vuln.cveId,
    description: vuln.description ?? "Have no des",
    type: threatType ?? "Spoofing",
    status: "Non mitigated",
    score: scoreData,
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
export async function loadCweMapping(): Promise<Record<string, ThreatType[]>> {
  try {
    // Use path.join with __dirname to create a cross-platform path
    const filePath = path.join(__dirname, '..', 'utils', 'cweToStride.json');
    // Read the file contents as a UTF-8 string
    const data = await fs.readFile(filePath, "utf8");
    // Parse the JSON content into an object
    const mapping: Record<string, ThreatType[]> = JSON.parse(data);
    return mapping;
  } catch (err) {
    console.error("Failed to load CWE mapping:", err);
    return {};
  }
}

let cweToStrideMap: any;

(async () => {
  cweToStrideMap = await loadCweMapping();
})();

/**
 * Thu thập tất cả các "phiếu bầu" (votes) tiềm năng cho một lỗ hổng bảo mật
 * @param vuln Đối tượng lỗ hổng cần phân tích
 * @returns Mảng các phiếu bầu với trọng số tương ứng
 */
export function getVotes(vuln: Vulnerability): Vote[] {
  const votes: Vote[] = [];

  // === (1) Map CWE to STRIDE ===
  // Analyze CWE codes and map to corresponding threat types
  // Highest weight (3) because CWE is a reliable vulnerability classification standard
  for (const cwe of vuln.cwes || []) {
    const mappedTypes = cweToStrideMap[cwe];
    if (mappedTypes) {
      for (const mappedType of mappedTypes) {
        votes.push({
          type: mappedType as ThreatType,
          source: "CWE",
          weight: sourceWeights["CWE"], // Weight = 3
        });
      }
    }
  }

  // === (2) Analyze keywords in description ===
  // Search for characteristic keywords in vulnerability description
  // Medium weight (2) because it's based on semantic analysis
  const desc = vuln.description?.toLowerCase() || "";

  // Keyword patterns for each threat type
  const keywordPatterns = {
    "Elevation of Privilege": /\b(privilege|permission|access control|unauthorized|admin|root|sudo)\b/,
    "Spoofing": /\b(spoof|impersonat|authentica|identity|credential|phish|forge)\b/,
    "Tampering": /\b(tamper|modify|alter|change|corrupt|inject|manipulate)\b/,
    "Repudiation": /\b(repudiat|logging|audit|track|monitor|log file|activity)\b/,
    "Information Disclosure": /\b(disclosure|leak|expose|sensitive|confidential|private|plaintext)\b/,
    "Denial of Service": /\b(denial|dos|crash|exhaust|flood|unavailable|resource)\b/
  };

  // Check each pattern and add vote if found
  for (const [threatType, pattern] of Object.entries(keywordPatterns)) {
    if (pattern.test(desc)) {
      votes.push({
        type: threatType as ThreatType,
        source: "Keyword",
        weight: sourceWeights["Keyword"] // Weight = 2
      });
    }
  }

  // === (3) Infer from severity ===
  // Map severity levels to threat types
  // Lowest weight (1) as this is the simplest inference method
  const severityMappings: Record<string, ThreatType[]> = {
    "CRITICAL": ["Elevation of Privilege", "Information Disclosure"],
    "HIGH": ["Information Disclosure", "Denial of Service"],
    "MEDIUM": ["Tampering", "Repudiation"],
    "LOW": ["Repudiation", "Spoofing"]
  };

  if (vuln.severity) {
    const mappedTypes = severityMappings[vuln.severity.toUpperCase()];
    if (mappedTypes) {
      for (const mappedType of mappedTypes) {
        votes.push({
          type: mappedType,
          source: "Severity",
          weight: sourceWeights["Severity"] // Weight = 1
        });
      }
    }
  }

  return votes;
}

/**
 * Xác định loại threat có khả năng xảy ra nhất từ các phiếu bầu
 * @param votes Mảng các phiếu bầu đã thu thập
 * @param artifactType Loại artifact đang được phân tích
 * @returns Loại threat phù hợp nhất hoặc null nếu không thể xác định
 */
export function resolveThreatType(votes: Vote[], artifactType: string): ThreatType | null {
  // Initialize score map for each threat type
  const scoreMap: Record<ThreatType, number> = {} as Record<ThreatType, number>;

  // Calculate total score for each threat type
  for (const vote of votes) {
    scoreMap[vote.type] = (scoreMap[vote.type] || 0) + vote.weight;
  }

  // Sort threats by score in descending order
  const sorted = Object.entries(scoreMap).sort((a, b) => b[1] - a[1]);

  // If no votes, return null
  if (sorted.length === 0) return null;

  // If no specific prioritization matched, return the highest scoring threat
  return sorted[0][0] as ThreatType;
}

// Hàm gộp danh sách lỗ hổng và loại bỏ trùng lặp
function mergeVulnerabilities(existingVulns: any[], newVulns: any[]): any[] {
  const merged = [...existingVulns];

  for (const newVuln of newVulns) {
    const exists = merged.some(v => v.cveId === newVuln.cveId);
    if (!exists) {
      merged.push(newVuln);
    }
  }

  return merged;
}

// Hàm xử lý kết quả từ một scanner
export async function processScannerResult(artifactId: string, vulns: any): Promise<void> {
  try {
    const artifact = await ArtifactModel.findById(artifactId);
    if (!artifact) {
      console.error(`Artifact ${artifactId} not found`);
      return;
    }

    // Initialize or update tempVuls
    artifact.tempVuls = mergeVulnerabilities(artifact.tempVuls || [], vulns);

    // Increment completed scanners count
    artifact.scannersCompleted = (artifact.scannersCompleted || 0) + 1;

    // Check if all scanners have completed
    if (artifact.scannersCompleted >= (artifact.totalScanners ?? 1)) {
      await updateArtifactAfterScan(artifact);
      // Reset counters and scanning state
      artifact.scannersCompleted = 0;
      artifact.totalScanners = 0;
      artifact.isScanning = false;
    }

    await artifact.save();

  } catch (error) {
    console.error("Error processing scanner result:", error);
    // Reset scanning state on error
    await ArtifactModel.findByIdAndUpdate(artifactId, { isScanning: false });
    throw error;
  }
}

/**
 * Kiểm tra threat có phù hợp với vulnerability không. 
 * Giả sử threat.name chứa định danh (ví dụ cveId) của vulnerability.
 */
function threatMatchesVul(threat: any, vuln: any): boolean {
  return threat.name === vuln.cveId;
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
  
  // Loại bỏ các threat đã bị xóa khỏi artifact.threatList (không xóa khỏi database)
  artifact.threatList = artifact.threatList.filter(
    (t: any) => !threatsToRemove.some((removeId: any) => removeId.toString() === t._id.toString())
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
      autoCreateTicketFromThreat(artifact._id, createdThreat._id);
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

    // 3. Lưu lịch sử quét vào scanHistory
    if (artifact.tempVuls && artifact.tempVuls.length > 0) {
      if (!artifact.scanHistory) {
        artifact.scanHistory = [];
      }

      // Add current scan to history
      artifact.scanHistory.push({
        timestamp: new Date(),
        vulnerabilities: artifact.tempVuls || []
      });

      console.log(`Added scan history entry with ${artifact.tempVuls.length} vulnerabilities`);
    }

    // 4. Gán lại vulnerabilityList bằng tempVuls và lưu artifact
    artifact.vulnerabilityList = artifact.tempVuls || [];
    artifact.tempVuls = [];
    await artifact.save();
    console.log(`Artifact ${artifact._id} đã được cập nhật với vulnerabilityList mới từ tempVuls.`);
  } catch (error) {
    console.error("Lỗi khi cập nhật artifact sau scan:", error);
    throw error;
  }
}

// Migrate artifacts to ensure they all have a state field
export async function migrateArtifactsState() {
  try {
    // Find all artifacts without a state field
    const artifacts = await ArtifactModel.find({ state: { $exists: false } });

    if (artifacts.length === 0) {
      return;
    }

    console.log(`[INFO] Found ${artifacts.length} artifacts without state field, applying migration`);

    // Update all artifacts to set default state to valid
    const updateResult = await ArtifactModel.updateMany(
      { state: { $exists: false } },
      { $set: { state: "valid" } }
    );

    console.log(`[INFO] Migration complete: ${updateResult.modifiedCount} artifacts updated`);
  } catch (error) {
    console.error("[ERROR] Failed to migrate artifact states:", error);
  }
}

// Run migration on startup
migrateArtifactsState();

// Get the phase ID that contains a specific artifact
export async function getPhaseForArtifact(req: Request, res: Response) {
  const { id } = req.params;
  try {
    // Find the phase that contains this artifact
    const phase = await PhaseModel.findOne({ artifacts: id }).select('_id name');
    
    if (!phase) {
      return res.json(errorResponse("Phase containing this artifact not found"));
    }

    return res.json(successResponse({ phaseId: phase._id, phaseName: phase.name }, "Phase found successfully"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}



