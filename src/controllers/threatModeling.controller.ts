import { Request, Response } from "express";
import { ThreatModel, ArtifactModel, MitigationModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import * as fs from 'fs/promises';
import * as path from 'path';
import mongoose from "mongoose";

interface MitigationStrategy {
  title: string;
  description: string;
  implementation: string;
}

// Lưu trữ dữ liệu JSON đã tải
let cvssVectorMappingData: Record<string, any>;
let securityInfoLinksData: Record<string, Record<string, string>>;

// Các thành phần dữ liệu giảm thiểu riêng biệt
let vulnerabilityCategoriesData: Record<string, MitigationStrategy>;
let strideCategoriesData: Record<string, MitigationStrategy>;
let complementaryMitigationsData: Record<string, MitigationStrategy>;
let cweMappingData: Record<string, string>;
let patternMatchingData: Record<string, string[]>;

/**
 * Tải tất cả các file cấu hình JSON khi khởi động
 */
async function loadJsonConfigs() {
  try {
    // Định nghĩa đường dẫn
    const basePath = path.resolve(__dirname, '../utils');
    
    // Tải file ánh xạ CVSS vector
    cvssVectorMappingData = JSON.parse(
      await fs.readFile(path.join(basePath, 'cvssVectorMapping.json'), 'utf8')
    );
    
    // Tải file liên kết thông tin bảo mật
    securityInfoLinksData = JSON.parse(
      await fs.readFile(path.join(basePath, 'securityInfoLinks.json'), 'utf8')
    );
    
    // Tải các file giảm thiểu đã tách riêng
    vulnerabilityCategoriesData = JSON.parse(
      await fs.readFile(path.join(basePath, 'vulnerabilityCategories.json'), 'utf8')
    );
    
    strideCategoriesData = JSON.parse(
      await fs.readFile(path.join(basePath, 'strideCategories.json'), 'utf8')
    );
    
    complementaryMitigationsData = JSON.parse(
      await fs.readFile(path.join(basePath, 'complementaryMitigations.json'), 'utf8')
    );
    
    cweMappingData = JSON.parse(
      await fs.readFile(path.join(basePath, 'cweMapping.json'), 'utf8')
    );
    
    patternMatchingData = JSON.parse(
      await fs.readFile(path.join(basePath, 'patternMatching.json'), 'utf8')
    );
    
    console.log("✅ All threat modeling data files loaded successfully");
  } catch (error) {
    console.error("❌ Error loading threat modeling data files:", error);
  }
}

// Khởi tạo bằng cách tải tất cả cấu hình
loadJsonConfigs().catch(console.error);

/**
 * Lấy thông tin chi tiết về mối đe dọa cho nút "Thông tin thêm"
 * 
 * Endpoint này cung cấp chi tiết kỹ thuật về một mối đe dọa, bao gồm:
 * - Điểm CVSS và mức độ nghiêm trọng
 * - Phân loại CWE
 * - Ngày xuất bản và tài liệu tham khảo
 * - Đánh giá rủi ro chi tiết
 * - Chi tiết kỹ thuật về lỗ hổng
 * 
 * @param {Request} req - Yêu cầu từ client chứa threatId
 * @param {Response} res - Phản hồi với thông tin chi tiết về mối đe dọa
 * @returns {Promise<Response>} - Phản hồi JSON
 */
export async function getDetailedThreatInfo(req: Request, res: Response) {
  const { id } = req.params;
  
  try {
    // Lấy mối đe dọa và dữ liệu lỗ hổng liên quan
    const threat = await ThreatModel.findById(id);
    
    if (!threat) {
      return res.json(errorResponse("Threat not found"));
    }
    
    // Tìm artifact nào đó chứa mối đe dọa này để lấy dữ liệu lỗ hổng
    const artifact = await ArtifactModel.findOne({
      threatList: id,
    });
    
    // Tìm lỗ hổng tương ứng dựa trên threat.name (là CVE ID)
    const relatedVulnerability = artifact?.vulnerabilityList?.find(
      (vuln) => vuln.cveId === threat.name
    );
    
    // Lấy ngữ cảnh mối đe dọa bổ sung dựa trên loại STRIDE
    const threatContext = getEnhancedThreatContext(threat.type, relatedVulnerability);
    
    // Chi tiết đánh giá rủi ro
    const riskAssessment = {
      affectedAssets: getAffectedAssets(threat.type),
      potentialImpacts: getPotentialImpacts(threat.type),
    };

    return res.json(
      successResponse(
        {
          threat,
          threatContext,
          riskAssessment,
          relatedVulnerability,
        },
        "Detailed threat information retrieved successfully"
      )
    );
  } catch (error) {
    console.error("Error retrieving detailed threat info:", error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}



/**
 * Lấy ngữ cảnh mối đe dọa nâng cao với liên kết chính thức cho các yếu tố thông tin
 * 
 * @param {string} threatType - Loại STRIDE của mối đe dọa
 * @param {any} vulnerability - Dữ liệu lỗ hổng liên quan nếu có
 * @returns {Object} - Thông tin ngữ cảnh nâng cao với liên kết chính thức
 */
function getEnhancedThreatContext(threatType: string, vulnerability: any = null) {

  // Tạo bản sao sâu để tránh sửa đổi bản gốc
  const enrichedContext: {
    description: string;
    commonAttackVectors: string[];
    securityPrinciples: string[];
  } = {
    description: "",
    commonAttackVectors: [],
    securityPrinciples: []
  };
    // Điều chỉnh ngữ cảnh dựa trên CVSS vector nếu có
  if (vulnerability && vulnerability.cvssVector) {
    const vectorAdjustments = getAdjustmentsFromCVSSVector(vulnerability.cvssVector, threatType);
    
    if (vectorAdjustments.attackVectors.length > 0) {
      // Ưu tiên những vector này
      enrichedContext.commonAttackVectors = [
        ...vectorAdjustments.attackVectors,
        ...enrichedContext.commonAttackVectors.filter(vector => 
          !vectorAdjustments.attackVectors.some(newVector => 
            vector.toLowerCase().includes(newVector.toLowerCase())
          )
        )
      ].slice(0, 8);
    }
    
    if (vectorAdjustments.securityPrinciples.length > 0) {
      // Ưu tiên những nguyên tắc này
      enrichedContext.securityPrinciples = [
        ...vectorAdjustments.securityPrinciples,
        ...enrichedContext.securityPrinciples.filter(principle => 
          !vectorAdjustments.securityPrinciples.some(newPrinciple => 
            principle.toLowerCase().includes(newPrinciple.toLowerCase())
          )
        )
      ].slice(0, 8);
    }
  }
  
  // Thêm liên kết chính thức vào ngữ cảnh
  return enrichContextWithLinks(enrichedContext);
}

/**
 * Làm phong phú thông tin ngữ cảnh với các liên kết chính thức
 * 
 * @param {Object} context - Thông tin ngữ cảnh cơ bản
 * @returns {Object} - Ngữ cảnh được làm phong phú với các liên kết chính thức
 */
function enrichContextWithLinks(context: any): any {
  // Tạo bản sao sâu của ngữ cảnh
  const enrichedContext = {
    description: context.description,
    commonAttackVectors: [],
    securityPrinciples: []
  };
  
  // Thêm thông tin liên kết vào các vector tấn công
  enrichedContext.commonAttackVectors = context.commonAttackVectors.map((vector: string) => {
    // Cố gắng tìm khớp chính xác hoặc khớp một phần trong dữ liệu liên kết
    for (const [key, url] of Object.entries(securityInfoLinksData.attackVectors)) {
      if (vector.toLowerCase().includes(key.toLowerCase()) || 
          key.toLowerCase().includes(vector.toLowerCase())) {
        return {
          text: vector,
          link: url
        };
      }
    }
    
    // Nếu không tìm thấy khớp nào, trả về với liên kết dự phòng
    return {
      text: vector,
      link: `${securityInfoLinksData.fallbackLink}?query=${encodeURIComponent(vector)}`
    };
  });
  
  // Thêm thông tin liên kết vào các nguyên tắc bảo mật
  enrichedContext.securityPrinciples = context.securityPrinciples.map((principle: string) => {
    // Cố gắng tìm khớp chính xác hoặc khớp một phần trong dữ liệu liên kết
    for (const [key, url] of Object.entries(securityInfoLinksData.securityPrinciples)) {
      if (principle.toLowerCase().includes(key.toLowerCase()) || 
          key.toLowerCase().includes(principle.toLowerCase())) {
        return {
          text: principle,
          link: url
        };
      }
    }
    
    // Nếu không tìm thấy khớp nào, trả về với liên kết chung
    return {
      text: principle,
      link: `https://cheatsheetseries.owasp.org/cheatsheets/Secure_Coding_Practices-Quick_Reference_Guide.html`
    };
  });
  
  return enrichedContext;
}

/**
 * Trích xuất các vector tấn công và nguyên tắc bảo mật từ chuỗi CVSS vector
 * 
 * @param {string} cvssVector - Chuỗi CVSS vector
 * @param {string} threatType - Loại mối đe dọa STRIDE
 * @returns {Object} - Đối tượng với các vector tấn công và nguyên tắc bảo mật
 */
function getAdjustmentsFromCVSSVector(cvssVector: string, threatType: string): {
  attackVectors: string[],
  securityPrinciples: string[]} {
  const attackVectors: string[] = [];
  const securityPrinciples: string[] = [];
  
  // Kiểm tra xem dữ liệu của chúng ta đã được tải chưa
  if (!cvssVectorMappingData) {
    console.error("CVSS vector mapping data not loaded");
    return { attackVectors, securityPrinciples };
  }
  
  // Phân tích các thành phần CVSS vector
  const cvssComponents = cvssVector.split('/');
  
  // Trích xuất các phần tử vector riêng lẻ (AV:N, AC:L, v.v.)
  cvssComponents.forEach(component => {
    const trimmedComponent = component.trim();
    
    // Tìm kiếm các vector tấn công từ dữ liệu JSON của chúng ta
    if (cvssVectorMappingData.attackVectors[trimmedComponent]) {
      attackVectors.push(cvssVectorMappingData.attackVectors[trimmedComponent].vector);
    }
    
    // Tìm kiếm các nguyên tắc bảo mật từ dữ liệu JSON của chúng ta
    if (cvssVectorMappingData.securityPrinciples[trimmedComponent]) {
      securityPrinciples.push(cvssVectorMappingData.securityPrinciples[trimmedComponent]);
    }
  });
  
  // Thêm các nguyên tắc cụ thể cho mối đe dọa nếu có các thành phần CVSS liên quan
  if (cvssVectorMappingData.threatSpecificPrinciples[threatType]) {
    const threatSpecific = cvssVectorMappingData.threatSpecificPrinciples[threatType];
    
    // Kiểm tra xem có điều kiện nào cho loại mối đe dọa này có trong CVSS vector không
    const hasRelevantCondition = threatSpecific.conditions.some((condition: string) => 
      cvssComponents.some(component => component.trim() === condition)
    );
    
    if (hasRelevantCondition) {
      securityPrinciples.push(...threatSpecific.principles);
    }
  }
  
  return {
    attackVectors,
    securityPrinciples
  };
}


/**
 * Lấy các tài sản có thể bị ảnh hưởng dựa trên loại mối đe dọa
 * 
 * @param {string} threatType - Loại STRIDE của mối đe dọa
 * @returns {string[]} - Mảng các tài sản có thể bị ảnh hưởng
 */
function getAffectedAssets(threatType: string): string[] {
  const assetsByThreatType: Record<string, string[]> = {
    "Spoofing": ["Authentication systems", "User accounts", "Identity providers", "Session management"],
    "Tampering": ["Databases", "Configuration files", "Input processing components", "Data storage"],
    "Repudiation": ["Logging systems", "Audit trails", "Transaction records", "Event monitoring"],
    "Information Disclosure": ["Databases", "File storage", "Communication channels", "Cache systems", "Debug logs"],
    "Denial of Service": ["Web servers", "API endpoints", "Resource pools", "Network infrastructure"],
    "Elevation of Privilege": ["Access control systems", "Permission management", "Administrative interfaces", "Security boundaries"]
  };
  
  return assetsByThreatType[threatType] || ["Multiple system components"];
}

/**
 * Lấy các tác động tiềm ẩn dựa trên loại mối đe dọa
 * 
 * @param {string} threatType - Loại STRIDE của mối đe dọa
 * @returns {string[]} - Mảng các tác động tiềm ẩn
 */
function getPotentialImpacts(threatType: string): string[] {
  const impactsByThreatType: Record<string, string[]> = {
    "Spoofing": ["Unauthorized access", "Identity theft", "Fraudulent actions", "Reputation damage"],
    "Tampering": ["Data corruption", "System misconfiguration", "Business logic corruption", "False information"],
    "Repudiation": ["Audit failure", "Compliance violations", "Inability to trace malicious actions", "Fraud"],
    "Information Disclosure": ["Privacy violations", "Intellectual property theft", "Compliance violations", "Competitive disadvantage"],
    "Denial of Service": ["Service unavailability", "Performance degradation", "Customer dissatisfaction", "Financial losses"],
    "Elevation of Privilege": ["Complete system compromise", "Unauthorized administrative access", "Lateral movement", "Data breach"]
  };
  
  return impactsByThreatType[threatType] || ["Multiple security impacts"];
}

/**
 * Lấy gợi ý giảm thiểu cho nút "Đề xuất sửa chữa"
 * 
 * Endpoint này cung cấp các khuyến nghị khả thi để khắc phục mối đe dọa:
 * - Chiến lược giảm thiểu chung và cụ thể
 * - Thực hành tốt nhất về bảo mật
 * - Ví dụ triển khai với đoạn mã
 * - Công cụ bảo mật được khuyến nghị
 * 
 * @param {Request} req - Yêu cầu từ client chứa threatId
 * @param {Response} res - Phản hồi với các bản sửa và giảm thiểu được đề xuất
 * @returns {Promise<Response>} - Phản hồi JSON
 */
export async function getSuggestedFixes(req: Request, res: Response) {
  const { id } = req.params;
  
  try {
// Xác thực ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.json(errorResponse("Invalid threat ID format"));
    }

    // Lấy mối đe dọa và populate các giảm thiểu của nó
    const threat = await ThreatModel.findById(id).populate('mitigations');
    
    if (!threat) {
      return res.json(errorResponse("Threat not found"));
    }
    
    // Tìm artifact nào đó chứa mối đe dọa này để lấy dữ liệu lỗ hổng
    const artifact = await ArtifactModel.findOne({
      threatList: id,
    });
    
    // Tìm lỗ hổng tương ứng dựa trên threat.name (là CVE ID)
    const relatedVulnerability = artifact?.vulnerabilityList?.find(
      (vuln) => vuln.cveId === threat.name
    );
  
    
// Kiểm tra xem mối đe dọa đã có các giảm thiểu có cấu trúc chưa
    const existingMitigations = threat.mitigations?.length ? 
      threat.mitigations.map((m: any) => ({
        _id: m._id,
        title: m.title,
        description: m.description,
        implementation: m.implementation,
        isImplemented: m.isImplemented
      })) : [];

    // Tạo gợi ý giảm thiểu mới dựa trên loại mối đe dọa
    const mitigationSuggestions = getMitigationSuggestions(
      threat.type,
      relatedVulnerability
    );
    
    return res.json(
      successResponse(
        {
          threat,
          existingMitigations,
          mitigationSuggestions,
        },
        "Mitigation suggestions retrieved successfully"
      )
    );
  } catch (error) {
    console.error("Error retrieving mitigation suggestions:", error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Lấy gợi ý giảm thiểu dựa trên loại mối đe dọa và dữ liệu lỗ hổng
 * 
 * @param {string} threatType - Loại STRIDE của mối đe dọa
 * @param {any} vulnerability - Dữ liệu lỗ hổng liên quan nếu có
 * @returns {Object} - Đối tượng chứa các giảm thiểu cụ thể
 */
function getMitigationSuggestions(threatType: string, vulnerability: any) {
  // Thu thập tất cả thông tin để thông báo cho chiến lược giảm thiểu của chúng ta
  const cwes = vulnerability?.cwes || [];
  const cvssVector = vulnerability?.cvssVector || "";
  const description = vulnerability?.description || "";
  const severity = vulnerability?.severity || "";
  
  // Tạo phân tích ngữ cảnh toàn diện từ tất cả thông tin có sẵn
  const context = analyzeVulnerabilityContext(threatType, cwes, cvssVector, description, severity);
  
  // Tạo 1-2 giảm thiểu tập trung dựa trên phân tích toàn diện
  const mitigations = [];
  
  // 1. Tạo giảm thiểu chính dựa trên ngữ cảnh
  const primaryMitigation = generatePrimaryMitigation(context);
  if (primaryMitigation) {
    mitigations.push(primaryMitigation);
  }
  
  // 2. Tùy chọn tạo giảm thiểu bổ sung nếu liên quan
  const secondaryMitigation = generateComplementaryMitigation(context, primaryMitigation?.title || "");
  if (secondaryMitigation) {
    mitigations.push(secondaryMitigation);
  }
  
  // Trả về các giảm thiểu tập trung
  return {
    specific: mitigations
  };
}

/**
 * Phân tích lỗ hổng để tạo ngữ cảnh toàn diện cho việc tạo giảm thiểu
 * 
 * @param {string} threatType - Loại STRIDE
 * @param {string[]} cwes - Các định danh CWE
 * @param {string} cvssVector - Chuỗi CVSS vector
 * @param {string} description - Mô tả lỗ hổng
 * @param {string} severity - Mức độ nghiêm trọng của lỗ hổng
 * @returns {Object} - Phân tích ngữ cảnh toàn diện
 */
function analyzeVulnerabilityContext(
  threatType: string,
  cwes: string[],
  cvssVector: string,
  description: string,
  severity: string
): any {
  // Xác định các đặc điểm chính của lỗ hổng
  const descriptionLower = description.toLowerCase();
  
  // 1. Đặc điểm vector tấn công
  const isNetworkBased = cvssVector.includes('AV:N');
  const isLocalAttack = cvssVector.includes('AV:L');
  const isAdjacentAttack = cvssVector.includes('AV:A');
  const isPhysicalAttack = cvssVector.includes('AV:P');
  
  // 2. Độ phức tạp tấn công
  const isLowComplexity = cvssVector.includes('AC:L');
  const isHighComplexity = cvssVector.includes('AC:H');
  
  // 3. Xác thực/quyền hạn cần thiết
  const noPrivRequired = cvssVector.includes('PR:N');
  const lowPrivRequired = cvssVector.includes('PR:L');
  const highPrivRequired = cvssVector.includes('PR:H');
  
  // 4. Tương tác người dùng
  const userInteractionRequired = cvssVector.includes('UI:R');
  const noUserInteraction = cvssVector.includes('UI:N');
  
  // 5. Đặc điểm tác động
  const highConfidentiality = cvssVector.includes('C:H');
  const highIntegrity = cvssVector.includes('I:H');
  const highAvailability = cvssVector.includes('A:H');
  const scopeChanged = cvssVector.includes('S:C');
  
  // 6. Ánh xạ CWE vào các loại lỗ hổng
  const vulnCategories = new Set<string>();
  
  // Kiểm tra xem mitigationTemplatesData đã được tải chưa
  if (vulnerabilityCategoriesData && cweMappingData && patternMatchingData) {
    // Ánh xạ CWE đã biết vào các loại lỗ hổng bằng ánh xạ của chúng ta
    cwes.forEach(cwe => {
      const cweNum = cwe.replace('CWE-', '');
      if (cweMappingData[cweNum]) {
        vulnCategories.add(cweMappingData[cweNum]);
      }
    });
    
    // 7. Phân tích mô tả cho ngữ cảnh bổ sung bằng các mẫu từ JSON
    if (description) {
      for (const [category, patterns] of Object.entries(patternMatchingData)) {
        // Kiểm tra xem có mẫu nào xuất hiện trong mô tả không
        const hasPattern = (patterns as string[]).some(pattern => 
          descriptionLower.includes(pattern.toLowerCase())
        );
        
        if (hasPattern) {
          vulnCategories.add(category);
        }
      }
    }
  }
  
  // 8. Xác định loại lỗ hổng chính dựa trên phân tích kết hợp
  let primaryVulnCategory = '';
  
  // Sử dụng loại lỗ hổng cụ thể nhất mà chúng ta đã xác định
  if (vulnCategories.size > 0) {
    // Một số loại quan trọng hơn những loại khác
    const categoryPriority = [
      'sql-injection', 'command-injection', 'xss', 'xxe', 'deserialization', 
      'path-traversal', 'ssrf', 'csrf', 'authentication', 'authorization',
      'crypto', 'info-exposure', 'resource-management', 'misconfiguration'
    ];
    
    for (const category of categoryPriority) {
      if (vulnCategories.has(category)) {
        primaryVulnCategory = category;
        break;
      }
    }
  }
  
  // 9. Phân tích các yếu tố cụ thể của mối đe dọa
  const isAuthenticationIssue = threatType === 'Spoofing' || vulnCategories.has('authentication');
  const isAuthorizationIssue = threatType === 'Elevation of Privilege' || vulnCategories.has('authorization');
  const isDataIntegrityIssue = threatType === 'Tampering' || highIntegrity;
  const isConfidentialityIssue = threatType === 'Information Disclosure' || highConfidentiality;
  const isAvailabilityIssue = threatType === 'Denial of Service' || highAvailability;
  const isAuditingIssue = threatType === 'Repudiation';
  
  // 10. Xác định mức độ quan trọng
  const isCritical = 
    (isNetworkBased && isLowComplexity && noPrivRequired) || // Dễ khai thác từ xa
    severity.toUpperCase() === 'CRITICAL' || 
    (highConfidentiality && highIntegrity && highAvailability); // Tác động cao trên tất cả CIA triad
  
  // Trả về ngữ cảnh toàn diện
  return {
    threatType,
    cwes,
    primaryVulnCategory,
    vulnCategories: Array.from(vulnCategories),
    isNetworkBased,
    isLocalAttack,
    isLowComplexity, 
    noPrivRequired,
    userInteractionRequired,
    highConfidentiality,
    highIntegrity,
    highAvailability,
    scopeChanged,
    severity,
    isAuthenticationIssue,
    isAuthorizationIssue,
    isDataIntegrityIssue,
    isConfidentialityIssue,
    isAvailabilityIssue,
    isAuditingIssue,
    isCritical,
    description
  };
}

/**
 * Tạo chiến lược giảm thiểu chính dựa trên ngữ cảnh toàn diện
 * 
 * @param {Object} context - Ngữ cảnh lỗ hổng toàn diện
 * @returns {MitigationStrategy|null} - Chiến lược giảm thiểu chính hoặc null
 */
function generatePrimaryMitigation(context: any): MitigationStrategy | null {
  // Kiểm tra xem chúng ta có các mẫu giảm thiểu đã tải chưa
  if (!vulnerabilityCategoriesData) {
    console.error("Mitigation templates not loaded");
    return null;
  }
  
  // 1. Cố gắng tìm giảm thiểu loại lỗ hổng cụ thể
  if (context.primaryVulnCategory && 
      vulnerabilityCategoriesData[context.primaryVulnCategory]) {
    
    // Lấy chiến lược giảm thiểu từ các mẫu của chúng ta
    const mitigation = vulnerabilityCategoriesData[context.primaryVulnCategory];
    
    // Thêm các sửa đổi cụ thể theo ngữ cảnh
    let description = mitigation.description;
    if (context.isCritical) {
      description = `Critical: ${description}`;
    }
    
    // Thêm chi tiết triển khai cụ thể theo ngữ cảnh nếu cần
    let implementation = mitigation.implementation;
    if (context.isNetworkBased && context.primaryVulnCategory === 'authentication') {
      implementation = `Implement multi-factor authentication. ${implementation}`;
    }
    
    return {
      title: mitigation.title,
      description: description,
      implementation: implementation
    };
  }
  
  // 2. Fall back to STRIDE-based general mitigation if nothing more specific was found
  return getGeneralMitigation(context.threatType);
}

/**
 * Tạo giảm thiểu bổ sung giải quyết một khía cạnh khác
 * 
 * @param {Object} context - Ngữ cảnh lỗ hổng toàn diện
 * @param {string} primaryTitle - Tiêu đề của giảm thiểu chính để tránh trùng lặp
 * @returns {MitigationStrategy|null} - Giảm thiểu bổ sung hoặc null
 */
function generateComplementaryMitigation(context: any, primaryTitle: string): MitigationStrategy | null {
  // Kiểm tra xem chúng ta có các mẫu giảm thiểu đã tải chưa
  if (!complementaryMitigationsData) {
    console.error("Mitigation templates not loaded");
    return null;
  }
  
  const descLower = context.description.toLowerCase();
  
  // Dựa trên ngữ cảnh kết hợp, xác định các khía cạnh khác nhau cần được giải quyết
  
  // Nếu chính tập trung vào phòng ngừa, thêm phát hiện/giám sát
  if (!primaryTitle.includes("Monitor") && !primaryTitle.includes("Detect") && context.isNetworkBased) {
    return complementaryMitigationsData.securityMonitoring;
  }
  
  // Nếu xử lý xác thực nhưng chính không giải quyết vấn đề mật khẩu cụ thể
  if (context.isAuthenticationIssue && !primaryTitle.includes("Password") && 
     (descLower.includes("password") || descLower.includes("credential"))) {
    return complementaryMitigationsData.passwordSecurity;
  }
  
  // Nếu xử lý dữ liệu nhạy cảm nhưng chính không giải quyết tối thiểu hóa
  if (context.isConfidentialityIssue && !primaryTitle.includes("Minimization") && 
     (descLower.includes("sensitive") || descLower.includes("personal") || descLower.includes("private"))) {
    return complementaryMitigationsData.dataMinimization;
  }
  
  // Nếu xử lý API nhưng chính không giải quyết bảo mật API cụ thể
  if (!primaryTitle.includes("API") && 
     (descLower.includes("api") || descLower.includes("endpoint") || descLower.includes("interface"))) {
    return complementaryMitigationsData.apiSecurity;
  }
  
  // Nếu xử lý DoS và vấn đề bộ nhớ nhưng chính không giải quyết bộ nhớ cụ thể
  if (context.isAvailabilityIssue && !primaryTitle.includes("Memory") && descLower.includes("memory")) {
    return complementaryMitigationsData.memoryProtection;
  }
  
  // Thêm dự phòng cho các vấn đề availability quan trọng
  if (context.isAvailabilityIssue && context.isCritical && !primaryTitle.includes("Redundancy")) {
    return complementaryMitigationsData.systemRedundancy;
  }
  
  // Nếu chúng ta không tìm thấy giảm thiểu bổ sung cụ thể, trả về null
  return null;
}

/**
 * Lấy giảm thiểu chung dựa trên loại STRIDE
 * 
 * @param {string} threatType - Loại STRIDE
 * @returns {MitigationStrategy} - Giảm thiểu chung dựa trên STRIDE
 */
function getGeneralMitigation(threatType: string): MitigationStrategy {
  // Kiểm tra xem chúng ta có các mẫu giảm thiểu đã tải chưa
  if (!strideCategoriesData) {
    console.error("Mitigation templates or STRIDE categories not loaded");
    return {
      title: "Implement Security Controls",
      description: "Address security vulnerability",
      implementation: "Implement proper input validation and output encoding. Apply security controls according to the vulnerability type. Follow security best practices for your specific technology stack."
    };
  }
  
  return strideCategoriesData[threatType] || {
    title: "Implement Security Controls",
    description: "Address security vulnerability",
    implementation: "Implement proper input validation and output encoding. Apply security controls according to the vulnerability type. Follow security best practices for your specific technology stack.",
    securityControls: ["Input Validation", "Output Encoding", "Security Best Practices"]
  };
}