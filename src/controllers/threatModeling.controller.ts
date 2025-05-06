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

// Store loaded JSON data
let cweMitigationsData: Record<string, MitigationStrategy>;
let cvssVectorMappingData: Record<string, any>;
let securityInfoLinksData: Record<string, Record<string, string>>;

// Separate mitigation data components
let vulnerabilityCategoriesData: Record<string, MitigationStrategy>;
let strideCategoriesData: Record<string, MitigationStrategy>;
let complementaryMitigationsData: Record<string, MitigationStrategy>;
let cweMappingData: Record<string, string>;
let patternMatchingData: Record<string, string[]>;

/**
 * Load all JSON configuration files at startup
 */
async function loadJsonConfigs() {
  try {
    // Define paths
    const basePath = path.resolve(__dirname, '../utils');
    
    cweMitigationsData = JSON.parse(
      await fs.readFile(path.join(basePath, 'cweMitigations.json'), 'utf8')
    );
    
    // Load the CVSS vector mapping file
    cvssVectorMappingData = JSON.parse(
      await fs.readFile(path.join(basePath, 'cvssVectorMapping.json'), 'utf8')
    );
    
    // Load the security info links file
    securityInfoLinksData = JSON.parse(
      await fs.readFile(path.join(basePath, 'securityInfoLinks.json'), 'utf8')
    );
    
    // Load the separated mitigation files
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

// Initialize by loading all configurations
loadJsonConfigs().catch(console.error);

/**
 * Get detailed threat information for "More Info" button
 * 
 * This endpoint provides technical details about a threat, including:
 * - CVSS score and severity
 * - CWE classifications
 * - Publication dates and references
 * - Detailed risk assessment
 * - Technical vulnerability details
 * 
 * @param {Request} req - Request from client containing threatId
 * @param {Response} res - Response with detailed threat information
 * @returns {Promise<Response>} - JSON response
 */
export async function getDetailedThreatInfo(req: Request, res: Response) {
  const { id } = req.params;
  
  try {
    // Get the threat and related vulnerability data
    const threat = await ThreatModel.findById(id);
    
    if (!threat) {
      return res.json(errorResponse("Threat not found"));
    }
    
    // Find any artifact containing this threat to get the vulnerability data
    const artifact = await ArtifactModel.findOne({
      threatList: id,
    });
    
    // Find the corresponding vulnerability based on threat.name (which is the CVE ID)
    const relatedVulnerability = artifact?.vulnerabilityList?.find(
      (vuln) => vuln.cveId === threat.name
    );
    
    // Get additional threat context based on STRIDE category
    const threatContext = getEnhancedThreatContext(threat.type, relatedVulnerability);
    
    // Risk assessment details
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
 * Get enhanced threat context with official links for the informational elements
 * 
 * @param {string} threatType - The STRIDE category of the threat
 * @param {any} vulnerability - The related vulnerability data if available
 * @returns {Object} - Enhanced context information with official links
 */
function getEnhancedThreatContext(threatType: string, vulnerability: any = null) {

  // Create a deep copy to avoid modifying the original
  const enrichedContext: {
    description: string;
    commonAttackVectors: string[];
    securityPrinciples: string[];
  } = {
    description: "",
    commonAttackVectors: [],
    securityPrinciples: []
  };
  
  // Adjust context based on CVSS vector if available
  if (vulnerability.cvssVector) {
    const vectorAdjustments = getAdjustmentsFromCVSSVector(vulnerability.cvssVector, threatType);
    
    if (vectorAdjustments.attackVectors.length > 0) {
      // Prioritize these vectors
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
      // Prioritize these principles
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
  
  // Add official links to the context
  return enrichContextWithLinks(enrichedContext);
}

/**
 * Extract attack vectors and security principles from CVSS vector string
 * 
 * @param {string} cvssVector - CVSS vector string
 * @param {string} threatType - STRIDE threat type
 * @returns {Object} - Object with attack vectors and security principles
 */
function getAdjustmentsFromCVSSVector(cvssVector: string, threatType: string): {
  attackVectors: string[],
  securityPrinciples: string[]} {
  const attackVectors: string[] = [];
  const securityPrinciples: string[] = [];
  
  // Check if our data is loaded
  if (!cvssVectorMappingData) {
    console.error("CVSS vector mapping data not loaded");
    return { attackVectors, securityPrinciples };
  }
  
  // Parse CVSS vector components
  const cvssComponents = cvssVector.split('/');
  
  // Extract individual vector elements (AV:N, AC:L, etc.)
  cvssComponents.forEach(component => {
    const trimmedComponent = component.trim();
    
    // Look up attack vectors from our JSON data
    if (cvssVectorMappingData.attackVectors[trimmedComponent]) {
      attackVectors.push(cvssVectorMappingData.attackVectors[trimmedComponent].vector);
    }
    
    // Look up security principles from our JSON data
    if (cvssVectorMappingData.securityPrinciples[trimmedComponent]) {
      securityPrinciples.push(cvssVectorMappingData.securityPrinciples[trimmedComponent]);
    }
  });
  
  // Add threat-specific principles if the relevant CVSS components are present
  if (cvssVectorMappingData.threatSpecificPrinciples[threatType]) {
    const threatSpecific = cvssVectorMappingData.threatSpecificPrinciples[threatType];
    
    // Check if any of the conditions for this threat type are present in the CVSS vector
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
 * Enrich context information with official links
 * 
 * @param {Object} context - The base context information
 * @returns {Object} - Context enriched with official links
 */
function enrichContextWithLinks(context: any): any {
  // Create a deep copy of the context
  const enrichedContext = {
    description: context.description,
    commonAttackVectors: [],
    securityPrinciples: []
  };
  
  // Add link information to attack vectors
  enrichedContext.commonAttackVectors = context.commonAttackVectors.map((vector: string) => {
    // Try to find exact matches or partial matches in the links data
    for (const [key, url] of Object.entries(securityInfoLinksData.attackVectors)) {
      if (vector.toLowerCase().includes(key.toLowerCase()) || 
          key.toLowerCase().includes(vector.toLowerCase())) {
        return {
          text: vector,
          link: url
        };
      }
    }
    
    // If no match is found, return with the fallback link
    return {
      text: vector,
      link: `${securityInfoLinksData.fallbackLink}?query=${encodeURIComponent(vector)}`
    };
  });
  
  // Add link information to security principles
  enrichedContext.securityPrinciples = context.securityPrinciples.map((principle: string) => {
    // Try to find exact matches or partial matches in the links data
    for (const [key, url] of Object.entries(securityInfoLinksData.securityPrinciples)) {
      if (principle.toLowerCase().includes(key.toLowerCase()) || 
          key.toLowerCase().includes(principle.toLowerCase())) {
        return {
          text: principle,
          link: url
        };
      }
    }
    
    // If no match is found, return with a general link
    return {
      text: principle,
      link: `https://cheatsheetseries.owasp.org/cheatsheets/Secure_Coding_Practices-Quick_Reference_Guide.html`
    };
  });
  
  return enrichedContext;
}

/**
 * Get potentially affected assets based on threat type
 * 
 * @param {string} threatType - The STRIDE category of the threat
 * @returns {string[]} - Array of potentially affected assets
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
 * Get potential impacts based on threat type
 * 
 * @param {string} threatType - The STRIDE category of the threat
 * @returns {string[]} - Array of potential impacts
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
 * Get mitigation suggestions for "Suggest Fix" button
 * 
 * This endpoint provides actionable recommendations for fixing a threat:
 * - General and specific mitigation strategies
 * - Security best practices
 * - Implementation examples with code snippets
 * - Recommended security tools
 * 
 * @param {Request} req - Request from client containing threatId
 * @param {Response} res - Response with suggested fixes and mitigations
 * @returns {Promise<Response>} - JSON response
 */
export async function getSuggestedFixes(req: Request, res: Response) {
  const { id } = req.params;
  
  try {
// Validate ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.json(errorResponse("Invalid threat ID format"));
    }

    // Get the threat and populate its mitigations
    const threat = await ThreatModel.findById(id).populate('mitigations');
    
    if (!threat) {
      return res.json(errorResponse("Threat not found"));
    }
    
    // Find any artifact containing this threat to get the vulnerability data
    const artifact = await ArtifactModel.findOne({
      threatList: id,
    });
    
    // Find the corresponding vulnerability based on threat.name (which is the CVE ID)
    const relatedVulnerability = artifact?.vulnerabilityList?.find(
      (vuln) => vuln.cveId === threat.name
    );
  
    
// Check if the threat already has structured mitigations
    const existingMitigations = threat.mitigations?.length ? 
      threat.mitigations.map((m: any) => ({
        _id: m._id,
        title: m.title,
        description: m.description,
        implementation: m.implementation,
        isImplemented: m.isImplemented
      })) : [];

    // Generate new mitigation suggestions based on threat type
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
 * Get mitigation suggestions based on threat type and vulnerability data
 * 
 * @param {string} threatType - The STRIDE category of the threat
 * @param {any} vulnerability - Related vulnerability data if available
 * @returns {Object} - Object containing specific mitigations
 */
function getMitigationSuggestions(threatType: string, vulnerability: any) {
  // Collect all information to inform our mitigation strategy
  const cwes = vulnerability?.cwes || [];
  const cvssVector = vulnerability?.cvssVector || "";
  const description = vulnerability?.description || "";
  const severity = vulnerability?.severity || "";
  
  // Create a comprehensive context analysis from all available information
  const context = analyzeVulnerabilityContext(threatType, cwes, cvssVector, description, severity);
  
  // Generate 1-2 focused mitigations based on the comprehensive analysis
  const mitigations = [];
  
  // 1. Generate primary mitigation based on context
  const primaryMitigation = generatePrimaryMitigation(context);
  if (primaryMitigation) {
    mitigations.push(primaryMitigation);
  }
  
  // 2. Optionally generate a complementary mitigation if relevant
  const secondaryMitigation = generateComplementaryMitigation(context, primaryMitigation?.title || "");
  if (secondaryMitigation) {
    mitigations.push(secondaryMitigation);
  }
  
  // Return the focused mitigations
  return {
    specific: mitigations
  };
}

/**
 * Analyze vulnerability to create a comprehensive context for mitigation generation
 * 
 * @param {string} threatType - STRIDE category
 * @param {string[]} cwes - CWE identifiers
 * @param {string} cvssVector - CVSS vector string
 * @param {string} description - Vulnerability description
 * @param {string} severity - Vulnerability severity
 * @returns {Object} - Comprehensive context analysis
 */
function analyzeVulnerabilityContext(
  threatType: string,
  cwes: string[],
  cvssVector: string,
  description: string,
  severity: string
): any {
  // Identify key vulnerability characteristics
  const descriptionLower = description.toLowerCase();
  
  // 1. Attack vector characteristics
  const isNetworkBased = cvssVector.includes('AV:N');
  const isLocalAttack = cvssVector.includes('AV:L');
  const isAdjacentAttack = cvssVector.includes('AV:A');
  const isPhysicalAttack = cvssVector.includes('AV:P');
  
  // 2. Attack complexity
  const isLowComplexity = cvssVector.includes('AC:L');
  const isHighComplexity = cvssVector.includes('AC:H');
  
  // 3. Authentication/privileges required
  const noPrivRequired = cvssVector.includes('PR:N');
  const lowPrivRequired = cvssVector.includes('PR:L');
  const highPrivRequired = cvssVector.includes('PR:H');
  
  // 4. User interaction
  const userInteractionRequired = cvssVector.includes('UI:R');
  const noUserInteraction = cvssVector.includes('UI:N');
  
  // 5. Impact characteristics
  const highConfidentiality = cvssVector.includes('C:H');
  const highIntegrity = cvssVector.includes('I:H');
  const highAvailability = cvssVector.includes('A:H');
  const scopeChanged = cvssVector.includes('S:C');
  
  // 6. Map CWEs to vulnerability categories
  const vulnCategories = new Set<string>();
  
  // Check if mitigationTemplatesData is loaded
  if (vulnerabilityCategoriesData && cweMappingData && patternMatchingData) {
    // Map known CWEs to vulnerability categories using our mapping
    cwes.forEach(cwe => {
      const cweNum = cwe.replace('CWE-', '');
      if (cweMappingData[cweNum]) {
        vulnCategories.add(cweMappingData[cweNum]);
      }
    });
    
    // 7. Analyze description for additional context using patterns from JSON
    if (description) {
      for (const [category, patterns] of Object.entries(patternMatchingData)) {
        // Check if any pattern appears in the description
        const hasPattern = (patterns as string[]).some(pattern => 
          descriptionLower.includes(pattern.toLowerCase())
        );
        
        if (hasPattern) {
          vulnCategories.add(category);
        }
      }
    }
  }
  
  // 8. Determine the primary vulnerability category based on combined analysis
  let primaryVulnCategory = '';
  
  // Use the most specific vulnerability category we've identified
  if (vulnCategories.size > 0) {
    // Some categories are more critical than others
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
  
  // 9. Analyze threat-specific factors
  const isAuthenticationIssue = threatType === 'Spoofing' || vulnCategories.has('authentication');
  const isAuthorizationIssue = threatType === 'Elevation of Privilege' || vulnCategories.has('authorization');
  const isDataIntegrityIssue = threatType === 'Tampering' || highIntegrity;
  const isConfidentialityIssue = threatType === 'Information Disclosure' || highConfidentiality;
  const isAvailabilityIssue = threatType === 'Denial of Service' || highAvailability;
  const isAuditingIssue = threatType === 'Repudiation';
  
  // 10. Determine criticality
  const isCritical = 
    (isNetworkBased && isLowComplexity && noPrivRequired) || // Easily exploitable remotely
    severity.toUpperCase() === 'CRITICAL' || 
    (highConfidentiality && highIntegrity && highAvailability); // High impact across CIA triad
  
  // Return comprehensive context
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
 * Generate the primary mitigation strategy based on comprehensive context
 * 
 * @param {Object} context - Comprehensive vulnerability context
 * @returns {MitigationStrategy|null} - Primary mitigation strategy or null
 */
function generatePrimaryMitigation(context: any): MitigationStrategy | null {
  // Check if we have mitigation templates loaded
  if (!vulnerabilityCategoriesData) {
    console.error("Mitigation templates not loaded");
    return null;
  }
  
  // 1. Try to find a specific vulnerability category mitigation
  if (context.primaryVulnCategory && 
      vulnerabilityCategoriesData[context.primaryVulnCategory]) {
    
    // Get the mitigation strategy from our templates
    const mitigation = vulnerabilityCategoriesData[context.primaryVulnCategory];
    
    // Add context-specific modifications
    let description = mitigation.description;
    if (context.isCritical) {
      description = `Critical: ${description}`;
    }
    
    // Add context-specific implementation details if needed
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
  
  // 2. If no specific vulnerability category was identified, try using CWE-specific mitigations
  if (context.cwes.length > 0) {
    for (const cwe of context.cwes) {
      const cweNumber = cwe.replace("CWE-", "");
      
      // Check if we have this CWE mapped to a vulnerability category
      if (cweMappingData[cweNumber]) {
        const vulnCategory = cweMappingData[cweNumber];
        const mitigation = vulnerabilityCategoriesData[vulnCategory];
        
        if (mitigation) {
          // Add context-specific details
          let implementation = mitigation.implementation;
          
          if (context.isNetworkBased) {
            implementation += " Since this is remotely exploitable, implement network-level protections as well.";
          }
          
          // Add threat-specific context
          if (context.isAuthenticationIssue) {
            implementation += " Verify identity thoroughly and implement strong authentication.";
          } else if (context.isAuthorizationIssue) {
            implementation += " Verify authorization for all sensitive operations.";
          } else if (context.isDataIntegrityIssue) {
            implementation += " Validate data integrity and implement cryptographic controls.";
          } else if (context.isConfidentialityIssue) {
            implementation += " Ensure sensitive data is properly classified and encrypted.";
          } else if (context.isAvailabilityIssue) {
            implementation += " Implement proper resource constraints and error handling.";
          } else if (context.isAuditingIssue) {
            implementation += " Ensure actions are properly logged and auditable.";
          }
          
          return {
            title: mitigation.title,
            description: `${context.isCritical ? 'Critical: ' : ''}${mitigation.description}`,
            implementation: implementation
          };
        }
      }
      
      // Fallback to using the CWE-specific mitigations from the cweMitigations.json file
      const key = `CWE-${cweNumber}`;
      const cweMitigation = cweMitigationsData[key];
      
      if (cweMitigation) {
        // Create a more detailed implementation based on threat type and context
        let implementation = cweMitigation.implementation;
        
        // Add context-specific details
        if (context.isNetworkBased) {
          implementation += " Since this is remotely exploitable, implement network-level protections as well.";
        }
        
        // Add threat-specific context
        if (context.isAuthenticationIssue) {
          implementation += " Verify identity thoroughly and implement strong authentication.";
        } else if (context.isAuthorizationIssue) {
          implementation += " Verify authorization for all sensitive operations.";
        } else if (context.isDataIntegrityIssue) {
          implementation += " Validate data integrity and implement cryptographic controls.";
        } else if (context.isConfidentialityIssue) {
          implementation += " Ensure sensitive data is properly classified and encrypted.";
        } else if (context.isAvailabilityIssue) {
          implementation += " Implement proper resource constraints and error handling.";
        } else if (context.isAuditingIssue) {
          implementation += " Ensure actions are properly logged and auditable.";
        }
        
        return {
          title: cweMitigation.title,
          description: `${context.isCritical ? 'Critical: ' : ''}${cweMitigation.description}`,
          implementation: implementation
        };
      }
    }
  }
  
  // 3. Try to determine from description patterns
  if (context.description) {
    const descLower = context.description.toLowerCase();
    
    for (const [category, patterns] of Object.entries(patternMatchingData)) {
      // Check if any pattern appears in the description
      const hasPattern = (patterns as string[]).some(pattern => 
        descLower.includes(pattern.toLowerCase())
      );
      
      if (hasPattern && vulnerabilityCategoriesData[category]) {
        const mitigation = vulnerabilityCategoriesData[category];
        
        return {
          title: mitigation.title,
          description: `${context.isCritical ? 'Critical: ' : ''}${mitigation.description}`,
          implementation: mitigation.implementation
        };
      }
    }
  }
  
  // 4. Fall back to STRIDE-based general mitigation if nothing more specific was found
  return getGeneralMitigation(context.threatType);
}

/**
 * Generate a complementary mitigation that addresses a different aspect
 * 
 * @param {Object} context - Comprehensive vulnerability context
 * @param {string} primaryTitle - Title of the primary mitigation to avoid duplication
 * @returns {MitigationStrategy|null} - Complementary mitigation or null
 */
function generateComplementaryMitigation(context: any, primaryTitle: string): MitigationStrategy | null {
  // Check if we have mitigation templates loaded
  if (!complementaryMitigationsData) {
    console.error("Mitigation templates not loaded");
    return null;
  }
  
  const descLower = context.description.toLowerCase();
  
  // Based on combined context, identify different aspects that should be addressed
  
  // If primary focused on prevention, add detection/monitoring
  if (!primaryTitle.includes("Monitor") && !primaryTitle.includes("Detect") && context.isNetworkBased) {
    return complementaryMitigationsData.securityMonitoring;
  }
  
  // If dealing with authentication but primary didn't address password issues specifically
  if (context.isAuthenticationIssue && !primaryTitle.includes("Password") && 
     (descLower.includes("password") || descLower.includes("credential"))) {
    return complementaryMitigationsData.passwordSecurity;
  }
  
  // If dealing with sensitive data but primary didn't address minimization
  if (context.isConfidentialityIssue && !primaryTitle.includes("Minimization") && 
     (descLower.includes("sensitive") || descLower.includes("personal") || descLower.includes("private"))) {
    return complementaryMitigationsData.dataMinimization;
  }
  
  // If dealing with APIs but primary didn't address API security specifically
  if (!primaryTitle.includes("API") && 
     (descLower.includes("api") || descLower.includes("endpoint") || descLower.includes("interface"))) {
    return complementaryMitigationsData.apiSecurity;
  }
  
  // If dealing with DoS and memory issues but primary didn't address memory specifically
  if (context.isAvailabilityIssue && !primaryTitle.includes("Memory") && descLower.includes("memory")) {
    return complementaryMitigationsData.memoryProtection;
  }
  
  // Add redundancy for critical availability issues
  if (context.isAvailabilityIssue && context.isCritical && !primaryTitle.includes("Redundancy")) {
    return complementaryMitigationsData.systemRedundancy;
  }
  
  // If we didn't find a specific complementary mitigation, return null
  return null;
}

/**
 * Get a general mitigation based on STRIDE category
 * 
 * @param {string} threatType - STRIDE category
 * @returns {MitigationStrategy} - General STRIDE-based mitigation
 */
function getGeneralMitigation(threatType: string): MitigationStrategy {
  // Check if we have mitigation templates loaded
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