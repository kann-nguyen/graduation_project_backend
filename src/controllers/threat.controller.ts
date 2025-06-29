import { Request, Response } from "express";
import mongoose from "mongoose";
import { ArtifactModel, ThreatModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import path from "path";
import * as fs from "fs/promises";
import { Threat } from "../models/threat";
import { Vulnerability } from "../models/vulnerability";

//////////////////////////
type ThreatType =
  | "Spoofing"
  | "Tampering"
  | "Repudiation"
  | "Information Disclosure"
  | "Denial of Service"
  | "Elevation of Privilege";

type VotingSource = "CWE" | "Keyword" | "Severity";

// Mẫu từ khóa cho từng loại mối đe dọa
const keywordPatterns = {
  "Elevation of Privilege": /\b(privilege|permission|access control|unauthorized|admin|root|sudo)\b/,
  "Spoofing": /\b(spoof|impersonat|authentica|identity|credential|phish|forge)\b/,
  "Tampering": /\b(tamper|modify|alter|change|corrupt|inject|manipulate)\b/,
  "Repudiation": /\b(repudiat|logging|audit|track|monitor|log file|activity)\b/,
  "Information Disclosure": /\b(disclosure|leak|expose|sensitive|confidential|private|plaintext)\b/,
  "Denial of Service": /\b(denial|dos|crash|exhaust|flood|unavailable|resource)\b/
};

const severityMappings: Record<string, ThreatType[]> = {
  "CRITICAL": ["Elevation of Privilege", "Information Disclosure"],
  "HIGH": ["Information Disclosure", "Denial of Service"],
  "MEDIUM": ["Tampering", "Repudiation"],
  "LOW": ["Repudiation", "Spoofing"]
};

interface Vote {
  type: ThreatType;
  source: VotingSource;
  weight: number;
}

// Quy tắc trọng số bầu chọn
const sourceWeights: Record<VotingSource, number> = {
  CWE: 3,
  Keyword: 2,
  Severity: 1,
};

//https://www.researchgate.net/publication/351864310_Towards_Practical_Cybersecurity_Mapping_of_STRIDE_and_CWE_-_a_Multi-perspective_Approach
export async function loadCweMapping(): Promise<Record<string, ThreatType[]>> {
  try {
    // Giải quyết đường dẫn đến file JSON
    const filePath = path.resolve("src\\utils\\cweToStride.json");
    // Đọc nội dung file dưới dạng chuỗi UTF-8
    const data = await fs.readFile(filePath, "utf8");
    // Phân tích nội dung JSON thành đối tượng
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

// Score calculation interface
interface ScoreComponents {
  damage: number;
  reproducibility: number;
  exploitability: number;
  affectedUsers: number;
  discoverability: number;
}

/**
 * Lấy danh sách tất cả các mối đe dọa (threats) từ cơ sở dữ liệu.
 */
export async function getAll(req: Request, res: Response) {
  try {
    const threats = await ThreatModel.find();
    return res.json(successResponse(threats, "Threats retrieved successfully"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Tạo một mối đe dọa mới nếu nó chưa tồn tại trong cơ sở dữ liệu.
 */
export async function create(req: Request, res: Response) {
  const { data } = req.body;
  try {
    // Kiểm tra xem threat đã tồn tại hay chưa dựa trên tên
    const threat = await ThreatModel.findOne({ name: data.name });
    if (threat) {
      return res.json(errorResponse(`Threat already exists`));
    }

    // Nếu chưa tồn tại, tạo mới threat trong database
    const newThreat = await ThreatModel.create(data);
    return res.json(
      successResponse(
        null,
        "Registered a new threat successfully. Threat is now available in the database"
      )
    );
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Lấy thông tin của một threat dựa trên ID.
 */
export async function get(req: Request, res: Response) {
  const { id } = req.params;

  // Validate the ID format
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json(errorResponse("Invalid threat ID format"));
  }

  try {
    // Directly query ThreatModel by ID
    const threat = await ThreatModel.findById(id);

    if (!threat) {
      return res.status(404).json(errorResponse("Threat not found"));
    }

    return res.json(successResponse(threat, "Threat retrieved successfully"));
  } catch (error) {
    console.error(`Error retrieving threat with ID ${id}:`, error);
    return res.status(500).json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Cập nhật trạng thái (status) và biện pháp giảm thiểu (mitigation) của một threat.
 */
export async function update(req: Request, res: Response) {
  const { data } = req.body;
  const { status, mitigation } = data;
  const { id } = req.params;
  try {
    // Directly update the threat in ThreatModel
    const updatedThreat = await ThreatModel.findByIdAndUpdate(
      id,
      { status, mitigation },
      { new: true }
    );

    if (!updatedThreat) {
      return res.json(errorResponse("Threat not found"));
    }

    return res.json(successResponse(null, "Threat updated successfully"));
  } catch (error) {
    console.error(`Error updating threat with ID ${id}:`, error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

// Tạo threat từ vulnerability
export function createThreatFromVuln(vuln: any): Partial<Threat> {
  const votes = getVotes(vuln);
  const threatType = resolveThreatType(votes);

  // Tính toán điểm số ban đầu dựa trên dữ liệu vulnerability
  let scoreData;
  try {
    // Import hàm tính toán từ threatModeling.controller
    scoreData = calculateScoresFromVulnerability(vuln);
  } catch (error) {
    console.error("Error calculating initial threat scores:", error);
    // Fallback về điểm số mặc định nếu tính toán thất bại
    scoreData = {
      total: vuln.score ? vuln.score / 2 : 2.5, // Chuyển đổi CVSS (0-10) sang thang đo của chúng ta (0-5)
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

/**
 * Thu thập tất cả các "phiếu bầu" (votes) tiềm năng cho một lỗ hổng bảo mật
 * @param vuln Đối tượng lỗ hổng cần phân tích
 * @returns Mảng các phiếu bầu với trọng số tương ứng
 */
export function getVotes(vuln: Vulnerability): Vote[] {
  const votes: Vote[] = [];

  // === (1) Ánh xạ CWE thành STRIDE ===
  // Phân tích mã CWE và ánh xạ thành các loại mối đe dọa tương ứng
  // Trọng số cao nhất (3) vì CWE là tiêu chuẩn phân loại lỗ hổng đáng tin cậy
  for (const cwe of vuln.cwes || []) {
    const mappedTypes = cweToStrideMap[cwe];
    if (mappedTypes) {
      for (const mappedType of mappedTypes) {
        votes.push({
          type: mappedType as ThreatType,
          source: "CWE",
          weight: sourceWeights["CWE"], // Trọng số = 3
        });
      }
    }
  }

  // === (2) Phân tích từ khóa trong mô tả ===
  // Tìm kiếm từ khóa đặc trưng trong mô tả lỗ hổng
  // Trọng số trung bình (2) vì dựa trên phân tích ngữ nghĩa
  const desc = vuln.description?.toLowerCase() || "";

  // Kiểm tra từng mẫu và thêm vote nếu tìm thấy
  for (const [threatType, pattern] of Object.entries(keywordPatterns)) {
    if (pattern.test(desc)) {
      votes.push({
        type: threatType as ThreatType,
        source: "Keyword",
        weight: sourceWeights["Keyword"] // Trọng số = 2
      });
    }
  }

  // === (3) Suy luận từ mức độ nghiêm trọng ===
  // Ánh xạ mức độ nghiêm trọng thành các loại mối đe dọa
  // Trọng số thấp nhất (1) vì đây là phương pháp suy luận đơn giản nhất

  if (vuln.severity) {
    const mappedTypes = severityMappings[vuln.severity.toUpperCase()];
    if (mappedTypes) {
      for (const mappedType of mappedTypes) {
        votes.push({
          type: mappedType,
          source: "Severity",
          weight: sourceWeights["Severity"] // Trọng số = 1
        });
      }
    }
  }

  return votes;
}

/**
 * Xác định loại threat có khả năng xảy ra nhất từ các phiếu bầu
 * @param votes Mảng các phiếu bầu đã thu thập
 * @returns Loại threat phù hợp nhất hoặc null nếu không thể xác định
 */
export function resolveThreatType(votes: Vote[]): ThreatType | null {
  // Khởi tạo bản đồ điểm số cho từng loại mối đe dọa
  const scoreMap: Record<ThreatType, number> = {} as Record<ThreatType, number>;

  // Tính tổng điểm cho từng loại mối đe dọa
  for (const vote of votes) {
    scoreMap[vote.type] = (scoreMap[vote.type] || 0) + vote.weight;
  }

  // Sắp xếp các mối đe dọa theo điểm số giảm dần
  const sorted = Object.entries(scoreMap).sort((a, b) => b[1] - a[1]);

  // Nếu không có vote nào, trả về null
  if (sorted.length === 0) return null;

  // Nếu không có ưu tiên cụ thể nào khớp, trả về mối đe dọa có điểm cao nhất
  return sorted[0][0] as ThreatType;
}


/**
 * Calculate threat scores based on vulnerability data using the DREAD model
 * 
 * DREAD scores are on a scale of 0-5:
 * - Damage: How much damage could the attack cause?
 * - Reproducibility: How easy is it to reproduce the attack?
 * - Exploitability: How hard is it to launch the attack?
 * - Affected users: How many users would the attack affect?
 * - Discoverability: How easy is it to discover the vulnerability?
 * 
 * @param {any} vulnerability - The vulnerability data to analyze
 * @returns {object} - An object containing the calculated scores
 */
export function calculateScoresFromVulnerability(vulnerability: any) {
  // Base values
  const scoreComponents: ScoreComponents = {
    damage: 0,
    reproducibility: 0,
    exploitability: 0,
    affectedUsers: 0,
    discoverability: 0
  };
  
  // Convert CVSS score (0-10) to our score range (0-5)
  const cvssScore = vulnerability.score || 0;
  const scaledCvssScore = cvssScore / 2; // Scale down from 0-10 to 0-5
  
  // Parse CVSS vector if available to extract more granular data
  const cvssVector = vulnerability.cvssVector || "";
  
  // Use severity as a general indicator
  const severity = vulnerability.severity ? vulnerability.severity.toUpperCase() : "";
  
  // Map severity to base score ranges (scaled to 0-5)
  const severityBaseScore = {
    'CRITICAL': 4.5, // 9/2
    'HIGH': 3.5,     // 7/2
    'MEDIUM': 2.5,   // 5/2
    'LOW': 1.5       // 3/2
  }[severity as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'] || 2.5;
  
  // 1. Calculate Damage score based on severity and impact from CVSS
  scoreComponents.damage = severityBaseScore;
  
  // Check if confidentiality impact is mentioned in CVSS vector
  if (cvssVector.includes('C:H')) scoreComponents.damage = Math.min(5, scoreComponents.damage + 1);
  if (cvssVector.includes('I:H')) scoreComponents.damage = Math.min(5, scoreComponents.damage + 0.5);
  
  // 2. Calculate Reproducibility score
  scoreComponents.reproducibility = 2.5; // Default is moderate (scaled from 5/2)
  
  // Adjust based on attack complexity from CVSS
  if (cvssVector.includes('AC:L')) scoreComponents.reproducibility = 4; // Low complexity = highly reproducible
  if (cvssVector.includes('AC:H')) scoreComponents.reproducibility = 1.5; // High complexity = less reproducible
  
  // 3. Calculate Exploitability score from CVSS or derive from score
  if (cvssVector.includes('E:')) {
    if (cvssVector.includes('E:U')) scoreComponents.exploitability = 1.5; // Unproven (scaled from 3/2)
    else if (cvssVector.includes('E:P')) scoreComponents.exploitability = 2.5; // Proof of Concept
    else if (cvssVector.includes('E:F')) scoreComponents.exploitability = 4; // Functional
    else if (cvssVector.includes('E:H')) scoreComponents.exploitability = 5; // High
  } else {
    // Derive from CVSS score as a fallback
    scoreComponents.exploitability = Math.min(5, scaledCvssScore * 0.8);
  }
  
  // 4. Calculate Affected Users score
  scoreComponents.affectedUsers = 2.5; // Default is moderate impact
  
  // Increase if availability impact is high
  if (cvssVector.includes('A:H')) scoreComponents.affectedUsers = 4;
  
  // Check for scope change which indicates broader impact
  if (cvssVector.includes('S:C')) scoreComponents.affectedUsers = Math.min(5, scoreComponents.affectedUsers + 1);
  
  // 5. Calculate Discoverability score
  // Most vulnerabilities that have CVEs are already discovered, so this tends to be high
  scoreComponents.discoverability = 4;
  
  // If attack complexity is high, discoverability might be lower
  if (cvssVector.includes('AC:H')) scoreComponents.discoverability = 2.5;
  
  // Calculate average score
  const totalScore = (
    scoreComponents.damage + 
    scoreComponents.reproducibility + 
    scoreComponents.exploitability + 
    scoreComponents.affectedUsers + 
    scoreComponents.discoverability
  ) / 5;
  
  // Ensure the score is never 0 if we have a real vulnerability
  const finalScore = cvssScore > 0 && totalScore === 0 ? scaledCvssScore : totalScore;
  
  // Convert scores to integer values if needed
  // Optionally, round to nearest integer or nearest 0.5
  const roundedComponents = {
    damage: Math.round(scoreComponents.damage * 2) / 2,
    reproducibility: Math.round(scoreComponents.reproducibility * 2) / 2,
    exploitability: Math.round(scoreComponents.exploitability * 2) / 2,
    affectedUsers: Math.round(scoreComponents.affectedUsers * 2) / 2,
    discoverability: Math.round(scoreComponents.discoverability * 2) / 2
  };
  
  return {
    total: Math.round(finalScore * 2) / 2, // Round to nearest 0.5
    details: roundedComponents
  };
}

/**
 * Utility function to recalculate scores for all threats with zero scores
 * This can be called via an API endpoint or run as a maintenance task
 */
export async function recalculateZeroScores(req: Request, res: Response) {
  try {
    // Find all threats with zero total scores
    const zeroScoreThreats = await ThreatModel.find({
      $or: [
        { 'score.total': 0 },
        { 
          $and: [
            { 'score.details.damage': 0 },
            { 'score.details.reproducibility': 0 },
            { 'score.details.exploitability': 0 },
            { 'score.details.affectedUsers': 0 },
            { 'score.details.discoverability': 0 }
          ]
        }
      ]
    });
    
    // Count of successfully updated threats
    let updatedCount = 0;
    
    // Process each threat with zero score
    for (const threat of zeroScoreThreats) {
      // Find any artifact containing this threat to get the vulnerability data
      const artifact = await ArtifactModel.findOne({
        threatList: threat._id
      });
      
      // Find the corresponding vulnerability based on threat.name (which is the CVE ID)
      const relatedVulnerability = artifact?.vulnerabilityList?.find(
        (vuln) => vuln.cveId === threat.name
      );
      
      // If we found a related vulnerability, calculate and update the score
      if (relatedVulnerability) {
        // Calculate scores based on vulnerability data
        const scores = calculateScoresFromVulnerability(relatedVulnerability);
        
        // Update the threat with the calculated scores
        await ThreatModel.findByIdAndUpdate(threat._id, {
          $set: {
            'score.total': scores.total,
            'score.details': {
              damage: scores.details.damage,
              reproducibility: scores.details.reproducibility,
              exploitability: scores.details.exploitability,
              affectedUsers: scores.details.affectedUsers,
              discoverability: scores.details.discoverability
            }
          }
        });
        
        updatedCount++;
      }
    }
    
    return res.json(
      successResponse(
        { 
          totalZeroScores: zeroScoreThreats.length,
          updatedCount: updatedCount 
        },
        `Found ${zeroScoreThreats.length} threats with zero scores, updated ${updatedCount} successfully.`
      )
    );
  } catch (error) {
    console.error('Error recalculating zero scores:', error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
