import { Request, Response } from "express";
import { ThreatModel, ArtifactModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import * as fs from 'fs/promises';
import * as path from 'path';
import { string } from "zod";

// Interfaces to type our JSON data
interface ThreatContext {
  description: string;
  commonAttackVectors: string[];
  securityPrinciples: string[];
}

interface MitigationStrategy {
  title: string;
  description: string;
  implementation: string;
  securityControls?: string[];
}

interface BestPractice {
  title: string;
  practices: string[];
  standards: string[];
}

interface ImplementationExample {
  title: string;
  language: string;
  description: string;
  code: string;
}

interface SecurityTool {
  name: string;
  description: string;
  url: string;
}

interface CweMitigation {
  title: string;
  description: string;
  implementation: string;
}

interface SeverityAction {
  title: string;
  description: string;
  implementation: string;
}

// Score calculation interface
interface ScoreComponents {
  damage: number;
  reproducibility: number;
  exploitability: number;
  affectedUsers: number;
  discoverability: number;
}

// Store loaded JSON data
let threatMitigationsData: Record<string, MitigationStrategy[]>;
let bestPracticesData: Record<string, BestPractice>;
let implementationExamplesData: Record<string, ImplementationExample[]>;
let securityToolsData: { common: SecurityTool[], [key: string]: SecurityTool[] };
let cweMitigationsData: Record<string, CweMitigation>;
let severityActionsData: Record<string, SeverityAction>;
let cvssVectorMappingData: Record<string, any>;
let securityInfoLinksData: Record<string, Record<string, string>>;

/**
 * Load all JSON configuration files at startup
 */
async function loadJsonConfigs() {
  try {
    // Define paths
    const basePath = path.resolve(__dirname, '../utils');
    
    threatMitigationsData = JSON.parse(
      await fs.readFile(path.join(basePath, 'threatMitigations.json'), 'utf8')
    );
    
    bestPracticesData = JSON.parse(
      await fs.readFile(path.join(basePath, 'threatBestPractices.json'), 'utf8')
    );
    
    implementationExamplesData = JSON.parse(
      await fs.readFile(path.join(basePath, 'implementationExamples.json'), 'utf8')
    );
    
    securityToolsData = JSON.parse(
      await fs.readFile(path.join(basePath, 'securityTools.json'), 'utf8')
    );
    
    cweMitigationsData = JSON.parse(
      await fs.readFile(path.join(basePath, 'cweMitigations.json'), 'utf8')
    );
    
    severityActionsData = JSON.parse(
      await fs.readFile(path.join(basePath, 'severityActions.json'), 'utf8')
    );
    
    // Load the new CVSS vector mapping file
    cvssVectorMappingData = JSON.parse(
      await fs.readFile(path.join(basePath, 'cvssVectorMapping.json'), 'utf8')
    );
    
    // Load the security info links file
    securityInfoLinksData = JSON.parse(
      await fs.readFile(path.join(basePath, 'securityInfoLinks.json'), 'utf8')
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
    
    // If vulnerability exists but threat score is zero, update the threat score
    if (relatedVulnerability && 
       (threat.score.total === 0 || 
        (threat.score.details.damage === 0 && 
        threat.score.details.reproducibility === 0 && 
        threat.score.details.exploitability === 0 && 
        threat.score.details.affectedUsers === 0 && 
        threat.score.details.discoverability === 0))) {
      
      // Calculate scores based on vulnerability data
      const scores = calculateScoresFromVulnerability(relatedVulnerability);
      
      // Update the threat with the calculated scores
      await ThreatModel.findByIdAndUpdate(id, {
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
      
      // Refresh the threat object with updated scores
      threat.score.total = scores.total;
      threat.score.details.damage = scores.details.damage;
      threat.score.details.reproducibility = scores.details.reproducibility;
      threat.score.details.exploitability = scores.details.exploitability;
      threat.score.details.affectedUsers = scores.details.affectedUsers;
      threat.score.details.discoverability = scores.details.discoverability;
    }
    
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
    
    // If vulnerability exists but threat score is zero, update the threat score
    if (relatedVulnerability && 
       (threat.score.total === 0 || 
        (threat.score.details.damage === 0 && 
        threat.score.details.reproducibility === 0 && 
        threat.score.details.exploitability === 0 && 
        threat.score.details.affectedUsers === 0 && 
        threat.score.details.discoverability === 0))) {
      
      // Calculate scores based on vulnerability data
      const scores = calculateScoresFromVulnerability(relatedVulnerability);
      
      // Update the threat with the calculated scores
      await ThreatModel.findByIdAndUpdate(id, {
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
    }
    
    // Get mitigation suggestions based on threat type
    const mitigationSuggestions = getMitigationSuggestions(
      threat.type,
      relatedVulnerability
    );
    
    // Add best practices for the specific threat type
    const bestPractices = getBestPracticesForThreatType(threat.type);
    
    // Implementation examples and code snippets
    const implementationExamples = getImplementationExamples(threat.type, relatedVulnerability);
    
    // Get recommended security tools
    const recommendedTools = getRecommendedTools(threat.type);
    
    return res.json(
      successResponse(
        {
          threat,
          mitigationSuggestions,
          bestPractices,
          implementationExamples,
          recommendedTools,
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
 * Get mitigation suggestions based on CWE IDs
 * 
 * @param {string[]} cwes - Array of CWE IDs from vulnerability
 * @returns {Array} - Array of mitigation suggestions
 */
function getCweMitigations(cwes: string[]) {
  const mitigations = [];
  
  // Add mitigations for each matched CWE
  for (const cwe of cwes) {
    const cweNumber = cwe.replace("CWE-", "");
    const key = `CWE-${cweNumber}`;
    
    if (cweMitigationsData[key]) {
      mitigations.push(cweMitigationsData[key]);
    }
  }
  
  return mitigations;
}

/**
 * Get severity-based action recommendations
 * 
 * @param {string} severity - Severity level of the vulnerability
 * @returns {Object|null} - Severity-specific action recommendation
 */
function getSeverityActions(severity: string) {
  const severityUpper = severity.toUpperCase();
  return severityActionsData[severityUpper] || severityActionsData['default'];
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
  securityPrinciples: string[]
} {
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
 * Get mitigation suggestions based on threat type and vulnerability data
 * 
 * @param {string} threatType - The STRIDE category of the threat
 * @param {any} vulnerability - Related vulnerability data if available
 * @returns {Object} - Object containing general and specific mitigations
 */
function getMitigationSuggestions(threatType: string, vulnerability: any) {
  // Get general mitigations based on threat type from loaded JSON
  const baseMitigations = threatMitigationsData[threatType] || threatMitigationsData['default'];
  
  const specifics = [];
  
  // Add vulnerability-specific mitigations if available
  if (vulnerability) {
    // Check for CWEs to provide more targeted suggestions
    if (vulnerability.cwes && vulnerability.cwes.length > 0) {
      const cweMitigations = getCweMitigations(vulnerability.cwes);
      specifics.push(...cweMitigations);
    }
    
    // Add severity-based recommendations
    if (vulnerability.severity) {
      const severityAction = getSeverityActions(vulnerability.severity);
      if (severityAction) {
        specifics.push(severityAction);
      }
    }
  }
  
  return {
    general: baseMitigations,
    specific: specifics,
  };
}

/**
 * Get best practices for each threat type
 * 
 * @param {string} threatType - The STRIDE category of the threat
 * @returns {Object} - Best practices for the threat type
 */
function getBestPracticesForThreatType(threatType: string): any {
  return bestPracticesData[threatType] || bestPracticesData['default'];
}

/**
 * Get implementation examples and code snippets based on threat type
 * 
 * @param {string} threatType - The STRIDE category of the threat
 * @param {any} vulnerability - Related vulnerability data if available
 * @returns {Array} - Array of implementation examples
 */
function getImplementationExamples(threatType: string, vulnerability: any): any[] {
  // Get base examples from loaded JSON
  const baseExamples = implementationExamplesData[threatType] || implementationExamplesData['default'];
  
  let examples = [...baseExamples];
  
  // Add vulnerability-specific examples if CWEs are available
  if (vulnerability?.cwes?.length > 0) {
    const cweExamples = getCweSpecificExamples(vulnerability.cwes);
    if (cweExamples) {
      examples.push(cweExamples);
    }
  }
  
  return examples;
}

/**
 * Get code examples specific to CWEs
 * 
 * @param {string[]} cwes - Array of CWE IDs
 * @returns {Object|null} - Code example specific to the CWE or null
 */
function getCweSpecificExamples(cwes: string[]): any | null {
  // Hard-coded examples for specific CWEs
  // These should be moved to JSON files in a future update
  
  if (cwes.includes('CWE-79')) {
    return {
      title: "XSS Prevention Example",
      language: "JavaScript",
      description: "Preventing Cross-Site Scripting",
      code: `
// React example with safe rendering
import React from 'react';
import DOMPurify from 'dompurify';

function SafeHtmlComponent({ userProvidedHtml }) {
  // Sanitize HTML before rendering
  const sanitizedHtml = DOMPurify.sanitize(userProvidedHtml);
  
  return <div dangerouslySetInnerHTML={{ __html: sanitizedHtml }} />;
}`
    };
  }
  
  if (cwes.includes('CWE-89')) {
    return {
      title: "SQL Injection Prevention",
      language: "JavaScript",
      description: "Using parameterized queries to prevent SQL injection",
      code: `
// Example with prepared statements in Node.js
const { Pool } = require('pg');
const pool = new Pool();

async function getUserById(userId) {
  try {
    // Use parameterized query instead of string concatenation
    const result = await pool.query(
      'SELECT * FROM users WHERE id = $1', 
      [userId] // Parameters passed separately
    );
    return result.rows[0];
  } catch (err) {
    console.error('Database error:', err);
    throw err;
  }
}`
    };
  }
  
  if (cwes.includes('CWE-78')) {
    return {
      title: "Command Injection Prevention",
      language: "JavaScript",
      description: "Safely executing system commands",
      code: `
// Example of safe command execution
const { execFile } = require('child_process');

function runSafeCommand(fileName, args) {
  return new Promise((resolve, reject) => {
    // Using execFile instead of exec prevents command injection
    execFile(fileName, args, (error, stdout, stderr) => {
      if (error) {
        return reject(error);
      }
      resolve({ stdout, stderr });
    });
  });
}`
    };
  }
  
  return null;
}

/**
 * Get recommended security tools based on threat type
 * 
 * @param {string} threatType - The STRIDE category of the threat
 * @returns {Array} - Array of recommended security tools
 */
function getRecommendedTools(threatType: string): any[] {
  const commonTools = securityToolsData.common || [];
  const specificTools = securityToolsData[threatType] || [];
  
  return [...specificTools, ...commonTools];
}