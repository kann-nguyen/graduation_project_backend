import { Request, Response } from "express";
import { ArtifactModel, ThreatModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import { Threat } from "../models/threat";
import { Vulnerability } from "../models/vulnerability";
import { Artifact } from "../models/artifact";

// Định nghĩa kiểu dữ liệu cho body request
interface RequestBody {
  eventCode: string;
  imageName: string;
  securityState: string,
  data: Array<{
    cveId: string;
    description: string;
    severity: string;
    score?: number;
  }>;
}

// Định nghĩa kiểu dữ liệu cho body request
interface DocsRequestBody {
  eventCode: string;
  artifact_id: string;
  securityState: string,
  data: {
    hasSensitiveData: boolean;
    policyCompliant: boolean;
  };
}



// Generate a threat from a vulnerability
function createThreatFromVuln(vuln: any, artifactType: string): Partial<Threat> {
  const votes = getVotes(vuln);
  const threatType = resolveThreatType(votes, artifactType);
  const baseScore = vuln.score || 5;
  return {
    name: vuln.cveId,
    description: vuln.description,
    type: threatType ?? "Unknown",
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

/**
 * Import danh sách lỗ hổng bảo mật (vulnerabilities) vào một artifact hình ảnh
 * @param {Request} req - Request từ client, chứa thông tin về hình ảnh và danh sách lỗ hổng
 * @param {Response} res - Response xác nhận import thành công hoặc lỗi
 * @returns {Promise<Response>} - Trả về JSON response
 */
export async function importVulnToImage(req: Request, res: Response) {
  const { eventCode, imageName, securityState, data }: RequestBody = req.body;

  try {
    console.log("Received request:", { eventCode, imageName, securityState });

    const [name, version] = imageName.split(":");
    const artifacts = await ArtifactModel.find({ name, version });

    if (!artifacts || artifacts.length === 0) {
      return res.json(
        errorResponse(`No artifact found with name ${name} and version ${version}`)
      );
    }

    // Update vulnerabilities
    console.log(`[+] Updating vulnerability list for artifact ${name}:${version}`);
    await ArtifactModel.updateMany({ name, version }, {
      $set: {
        state: securityState,
        vulnerabilityList: data,
      },
    });

    // Tạo threat từ mỗi vulnerability bằng voting engine
    let totalThreats = 0;

    for (const artifact of artifacts) {
      for (const vuln of data as Vulnerability[]) {
        const threat = createThreatFromVuln(vuln, artifact.type);
        if (!threat) continue;

        const inserted: Threat = await ThreatModel.create(threat);

        artifact.threatList = artifact.threatList || [];
        artifact.threatList.push(inserted._id);
        totalThreats++;
      }
      await artifact.save();
    }
    

    console.log(`[+] Inserted ${totalThreats} threats across ${artifacts.length} artifacts`);

    return res.json(
      successResponse(null, `Imported vulnerabilities and created ${totalThreats} threats`)
    );
  } catch (error) {
    console.error("Error during importVulnToImage:", error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}


export async function importVulnToDocs(req: Request, res: Response) {
  const { eventCode, artifact_id, securityState, data }: DocsRequestBody = req.body;
  try {
    // Tìm các artifact có cùng tên và phiên bản
    const artifacts = await ArtifactModel.find({artifact_id});
    
    // Kiểm tra nếu không tìm thấy artifact phù hợp
    if (!artifacts) {
      return res.json(
        errorResponse(
          `No artifact found with id ${artifact_id}`
        )
      );
    }
    
    // Cập nhật danh sách vulnerabilities cho các artifact tìm thấy
    await ArtifactModel.updateMany(
      { artifact_id },
      {
        $set: {
          state: securityState
        },
      }
    );
    
    return res.json(
      successResponse(null, "Successfully imported vulnerabilities")
    );
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
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

// === Mapping Table ===
const cweToStrideMap: Record<string, Threat["type"]> = {
  "CWE-79": "Tampering",
  "CWE-89": "Tampering",
  "CWE-522": "Spoofing",
  "CWE-287": "Spoofing",
  "CWE-200": "Information Disclosure",
  "CWE-400": "Denial of Service",
  "CWE-284": "Elevation of Privilege",
  // ... bổ sung thêm nếu cần
};

function resolveThreatType(votes: Vote[], artifactType: string): ThreatType | null {
  const invalidCombos: Record<string, ThreatType[]> = {
    docs: ["Tampering", "Elevation of Privilege"],
    log: ["Elevation of Privilege"],
  };

  const filteredVotes = votes.filter(
    (v) => !invalidCombos[artifactType]?.includes(v.type)
  );

  const scoreMap: Record<ThreatType, number> = {} as any;
  for (const vote of filteredVotes) {
    scoreMap[vote.type] = (scoreMap[vote.type] || 0) + vote.weight;
  }

  const sorted = Object.entries(scoreMap).sort((a, b) => b[1] - a[1]);
  return sorted.length > 0 ? (sorted[0][0] as ThreatType) : null;
}

function getVotes(vuln: Vulnerability): Vote[] {
  const votes: Vote[] = [];

  // (1) CWE mapping
  for (const cwe of vuln.cwes || []) {
    const type = cweToStrideMap[cwe];
    if (type) {
      votes.push({
        type: type as ThreatType, // 👈 ép kiểu rõ ràng tại đây
        source: "CWE",
        weight: sourceWeights.CWE,
      });
    }
  }

  // (2) Keyword matching
  const desc = vuln.description?.toLowerCase() || "";
  if (/privilege|unauthorized/.test(desc)) votes.push({ type: "Elevation of Privilege", source: "Keyword", weight: 2 });
  if (/spoof|impersonation/.test(desc)) votes.push({ type: "Spoofing", source: "Keyword", weight: 2 });
  if (/denial|crash/.test(desc)) votes.push({ type: "Denial of Service", source: "Keyword", weight: 2 });
  if (/leak|plaintext/.test(desc)) votes.push({ type: "Information Disclosure", source: "Keyword", weight: 2 });

  // (3) Severity hint
  if (vuln.severity === "Critical") votes.push({ type: "Elevation of Privilege", source: "Severity", weight: 1 });
  else if (vuln.severity === "High") votes.push({ type: "Tampering", source: "Severity", weight: 1 });

  return votes;
}
