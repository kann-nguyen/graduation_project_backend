import { isDocumentArray } from "@typegoose/typegoose";
import { Request, Response } from "express";
import { ArtifactModel, ProjectModel, ThreatModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import { Artifact } from "../models/artifact";
import { Vulnerability } from "../models/vulnerability";
import { Threat } from "../models/threat";
import path from "path";
import * as fs from "fs/promises";

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
export async function generateAndAttachThreats(req: Request, res: Response) {
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
      console.log(`⚙️ Created threat from CVE ${vuln.cveId}:`, threatData);

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
  console.log("Loaded CWE to Threat Mapping:", cweToStrideMap);
})();

// Collect all potential threat "votes" for a given vulnerability
export function getVotes(vuln: Vulnerability): Vote[] {
  const votes: Vote[] = [];

  console.log("🔍 Analyzing Vulnerability:", vuln);

  // === (1) CWE Mapping ===
  for (const cwe of vuln.cwes || []) {
    const mappedType = cweToStrideMap[cwe] ?? "Spoofing";
    if (mappedType) {
      votes.push({
        type: mappedType as ThreatType,
        source: "CWE",
        weight: sourceWeights["CWE"],
      });
      console.log(`✅ Mapped CWE ${cwe} to ${mappedType}`);
    } else {
      console.log(`⚠️ No mapping found for CWE ${cwe}`);
    }
  }

  // === (2) Keyword Matching in Description ===
  const desc = vuln.description?.toLowerCase() || "have no des";

  if (/privilege|unauthorized/.test(desc)) {
    votes.push({ type: "Elevation of Privilege", source: "Keyword", weight: sourceWeights["Keyword"] });
    console.log("🔑 Matched keyword for Elevation of Privilege");
  }

  if (/spoof|impersonation/.test(desc)) {
    votes.push({ type: "Spoofing", source: "Keyword", weight: sourceWeights["Keyword"] });
    console.log("🔑 Matched keyword for Spoofing");
  }

  if (/denial|crash/.test(desc)) {
    votes.push({ type: "Denial of Service", source: "Keyword", weight: sourceWeights["Keyword"] });
    console.log("🔑 Matched keyword for Denial of Service");
  }

  if (/leak|plaintext/.test(desc)) {
    votes.push({ type: "Information Disclosure", source: "Keyword", weight: sourceWeights["Keyword"] });
    console.log("🔑 Matched keyword for Information Disclosure");
  }

  // === (3) Severity-based Inference ===
  if (vuln.severity === "Critical") {
    votes.push({ type: "Elevation of Privilege", source: "Severity", weight: sourceWeights["Severity"] });
    console.log("🔥 Critical severity → Elevation of Privilege");
  } else if (vuln.severity === "High") {
    votes.push({ type: "Tampering", source: "Severity", weight: sourceWeights["Severity"] });
    console.log("⚠️ High severity → Tampering");
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

  console.log(`📦 Resolving threat type for artifact type: ${artifactType}`);

  // Remove votes that are not valid for the given artifact type
  const filteredVotes = votes.filter(
    (vote) => !invalidCombos[artifactType]?.includes(vote.type)
  );

  console.log("🧹 Filtered Votes:", filteredVotes);

  const scoreMap: Record<ThreatType, number> = {} as Record<ThreatType, number>;

  // Calculate scores
  for (const vote of filteredVotes) {
    scoreMap[vote.type] = (scoreMap[vote.type] || 0) + vote.weight;
  }

  console.log("📊 Score Map:", scoreMap);

  // Sort threat types by their score descending
  const sorted = Object.entries(scoreMap).sort((a, b) => b[1] - a[1]);

  const result = sorted.length > 0 ? (sorted[0][0] as ThreatType) : null;
  console.log("✅ Final resolved threat type:", result);

  return result;
}




