import express from "express";
import { spawn } from "child_process";
import { randomUUID } from "crypto";
import "dotenv/config";
import { mkdir, readFile, unlink } from "fs/promises";
import axios from "axios";

const app = express();
const port = 3000;

// Vulnerability Standardization System
class VulnerabilityStandardizer {
  constructor() {
    this.cweToThreatMapping = new Map([
      ['CWE-79', ['Tampering', 'Information Disclosure']], // XSS
      ['CWE-89', ['Tampering', 'Information Disclosure']], // SQL Injection
      ['CWE-287', ['Spoofing']], // Authentication bypass
      ['CWE-285', ['Elevation of Privilege']], // Authorization
      ['CWE-200', ['Information Disclosure']], // Info exposure
      ['CWE-400', ['Denial of Service']], // Resource exhaustion
      ['CWE-352', ['Tampering']], // CSRF
      ['CWE-502', ['Tampering', 'Elevation of Privilege']], // Deserialization
    ]);
    
    this.keywordToThreatMapping = new Map([
      ['authentication', ['Spoofing']],
      ['authorization', ['Elevation of Privilege']],
      ['injection', ['Tampering', 'Information Disclosure']],
      ['xss', ['Tampering', 'Information Disclosure']],
      ['csrf', ['Tampering']],
      ['disclosure', ['Information Disclosure']],
      ['denial', ['Denial of Service']],
      ['privilege', ['Elevation of Privilege']],
      ['logging', ['Repudiation']],
    ]);
  }

  standardizeVulnerability(rawVuln, scannerType) {
    const basicStandardized = {
      cveId: rawVuln.cveId || rawVuln.id || 'UNKNOWN',
      severity: rawVuln.severity || 'Unknown',
      description: rawVuln.description || rawVuln.message || '',
      score: rawVuln.score || null,
      cvssVector: rawVuln.cvssVector || null,
      cwes: rawVuln.cwes || null
    };
    
    const threatContext = this.mapVulnerabilityToThreat(basicStandardized);
    
    return {
      ...basicStandardized,
      threatType: threatContext.primaryThreatType,
      threatCategories: [threatContext.primaryThreatType, ...threatContext.alternativeTypes],
      riskLevel: this.calculateRiskLevel(basicStandardized)
    };
  }

  mapVulnerabilityToThreat(vuln) {
    const votes = [];

    // Analyze CWEs
    if (vuln.cwes && vuln.cwes.length > 0) {
      vuln.cwes.forEach(cwe => {
        const threatTypes = this.cweToThreatMapping.get(cwe);
        if (threatTypes) {
          threatTypes.forEach(type => {
            votes.push({ type, weight: 3, reason: `CWE ${cwe} maps to ${type}` });
          });
        }
      });
    }

    // Analyze description keywords
    if (vuln.description) {
      const desc = vuln.description.toLowerCase();
      for (const [keyword, threatTypes] of this.keywordToThreatMapping.entries()) {
        if (desc.includes(keyword)) {
          threatTypes.forEach(type => {
            votes.push({ type, weight: 2, reason: `Contains "${keyword}" keyword` });
          });
        }
      }
    }

    // Calculate threat type scores
    const threatScores = new Map();
    votes.forEach(vote => {
      if (!threatScores.has(vote.type)) {
        threatScores.set(vote.type, { score: 0, reasons: [] });
      }
      const current = threatScores.get(vote.type);
      current.score += vote.weight;
      current.reasons.push(vote.reason);
    });

    const sortedThreats = Array.from(threatScores.entries())
      .sort(([,a], [,b]) => b.score - a.score);

    return {
      primaryThreatType: sortedThreats.length > 0 ? sortedThreats[0][0] : 'Information Disclosure',
      confidence: sortedThreats.length > 0 ? Math.min(sortedThreats[0][1].score / 5, 1) : 0.5,
      reasoning: sortedThreats.length > 0 ? sortedThreats[0][1].reasons : [],
      alternativeTypes: sortedThreats.slice(1, 3).map(([type]) => type)
    };
  }

  calculateRiskLevel(vuln) {
    if (vuln.score === null) return 'UNKNOWN';
    if (vuln.score >= 9) return 'CRITICAL';
    if (vuln.score >= 7) return 'HIGH';
    if (vuln.score >= 4) return 'MEDIUM';
    return 'LOW';
  }
}

// Vulnerability Adapters
class VulnerabilityAdapter {
  adapt(rawResult) { throw new Error('Must implement adapt method'); }
  getScannerType() { throw new Error('Must implement getScannerType method'); }
}

class SonarQubeAdapter extends VulnerabilityAdapter {
  getScannerType() { return 'sonarqube'; }

  adapt(rawResult) {
    const issues = rawResult.issues || [];
    return issues.map(issue => ({
      cveId: this.extractCveId(issue) || issue.rule || issue.key,
      severity: this.mapSeverity(issue.severity),
      description: issue.message,
      score: this.estimateScore(issue.severity),
      cvssVector: null,
      cwes: this.extractCwes(issue.tags || [])
    }));
  }

  mapSeverity(sonarSeverity) {
    const severityMap = {
      'BLOCKER': 'Critical',
      'CRITICAL': 'Critical',
      'MAJOR': 'High',
      'MINOR': 'Medium',
      'INFO': 'Low'
    };
    return severityMap[sonarSeverity] || 'Unknown';
  }

  extractCveId(issue) {
    if (issue.message && issue.message.includes('CVE-')) {
      const cveMatch = issue.message.match(/CVE-\d{4}-\d{4,}/);
      return cveMatch ? cveMatch[0] : null;
    }
    return null;
  }

  extractCwes(tags) {
    const cweFromTags = tags.filter(tag => 
      tag.startsWith('cwe') || tag.includes('cwe') || tag.startsWith('CWE')
    );
    return cweFromTags.length > 0 ? cweFromTags : null;
  }

  estimateScore(severity) {
    const scoreMap = {
      'BLOCKER': 9.5,
      'CRITICAL': 8.5,
      'MAJOR': 6.0,
      'MINOR': 3.0,
      'INFO': 1.0
    };
    return scoreMap[severity] || null;
  }
}

class GrypeAdapter extends VulnerabilityAdapter {
  getScannerType() { return 'grype'; }

  adapt(rawResult) {
    const matches = rawResult.matches || [];
    return matches.map(match => ({
      cveId: match.vulnerability.id,
      severity: match.vulnerability.severity,
      description: match.vulnerability.description,
      score: match.vulnerability.cvss?.[0]?.metrics?.baseScore || null,
      cvssVector: match.vulnerability.cvss?.[0]?.vector || null,
      cwes: match.vulnerability.cwe || null
    }));
  }
}

// Adapter Factory
class AdapterFactory {
  static adapters = new Map([
    ['sonarqube', new SonarQubeAdapter()],
    ['grype', new GrypeAdapter()]
  ]);

  static getAdapter(scannerType) {
    return this.adapters.get(scannerType.toLowerCase()) || null;
  }

  static registerAdapter(scannerType, adapter) {
    this.adapters.set(scannerType.toLowerCase(), adapter);
  }
}

// Process results with adapter
async function processResultWithAdapter(rawResult, scannerType) {
  const adapter = AdapterFactory.getAdapter(scannerType);
  
  if (!adapter) {
    log(`No adapter found for scanner type: ${scannerType}`, "ERROR");
    return [];
  }
  
  try {
    const standardizer = new VulnerabilityStandardizer();
    const standardVulns = adapter.adapt(rawResult);
    
    // Add threat mapping information to each vulnerability
    const enhancedVulns = standardVulns.map(vuln => {
      const enhanced = standardizer.standardizeVulnerability(vuln, scannerType);
      log(`Mapped ${enhanced.cveId} to threat type: ${enhanced.threatType}`);
      return enhanced;
    });
    
    log(`Standardized ${enhancedVulns.length} vulnerabilities with threat mappings`);
    return enhancedVulns;
  } catch (error) {
    log(`Error standardizing results: ${error.message}`, "ERROR");
    return [];
  }
}

// Add middleware to parse JSON in query params
app.use((req, res, next) => {
  if (req.query.artifact) {
    try {
      req.query.artifact = JSON.parse(decodeURIComponent(req.query.artifact));
    } catch (error) {
      return res.status(400).json({ error: "Invalid artifact format" });
    }
  }
  next();
});

function log(message, type = "INFO") {
  console.log(`[${new Date().toISOString()}] [${type}] ${message}`);
}

// CVE Information Service - fetches complete vulnerability data from various APIs
class CveInfoService {
  // API URLs
  static APIs = {
    // CircleCi provides a CVE lookup service - no API key required
    circleCI: "https://cve.circl.lu/api/cve/",
    
    // NIST NVD API - rate limited but official data
    nvd: "https://services.nvd.nist.gov/rest/json/cves/2.0",
  };

  // Rate limiting and circuit breaker state
  static rateLimiters = {
    circleCI: { lastRequest: 0, minInterval: 6000 },  // 10 req/min (with buffer)
    nvd: { lastRequest: 0, minInterval: 6000 },       // 10 req/min (with buffer)
  };

  static async getCveInfo(cveId) {
    try {
      log(`Fetching information for ${cveId}`);

      // Try NVD API if CircleCi didn't return data
      // We try this even without an API key, but it might fail with rate limits
      const nvdData = await this.fetchFromNvd(cveId);
      if (nvdData) {
        log(`Retrieved ${cveId} data from NVD API`);
        return {
          score: this.extractScoreFromNvd(nvdData),
          cvssVector: this.extractVectorFromNvd(nvdData),
          cwes: this.extractCwesFromNvd(nvdData)
        };
      }

      // Try CircleCi first - generally reliable and no authentication needed
      const circleData = await this.fetchFromCircleCi(cveId);
      if (circleData) {
        log(`Retrieved ${cveId} data from CircleCi API`);
        return {
          score: this.extractScoreFromCircleCi(circleData),
          cvssVector: this.extractVectorFromCircleCi(circleData),
          cwes: this.extractCwesFromCircleCi(circleData)
        };
      }

      log(`Could not find data for ${cveId} in any API`, "WARN");
      return null;

    } catch (error) {
      log(`Error fetching CVE info: ${error.message}`, "ERROR");
      return null;
    }
  }

  // Throttle requests to respect API rate limits
  static async throttleRequest(api) {
    const now = Date.now();
    const limiter = this.rateLimiters[api];
    
    if (!limiter) return;
    
    const elapsed = now - limiter.lastRequest;
    if (elapsed < limiter.minInterval) {
      const delay = limiter.minInterval - elapsed;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
    
    this.rateLimiters[api].lastRequest = Date.now();
  }

  // CircleCi API methods
  static async fetchFromCircleCi(cveId) {
    try {
      await this.throttleRequest('circleCI');
      const response = await axios.get(`${this.APIs.circleCI}${cveId}`, {
        timeout: 5000
      });
      
      if (response.status === 200 && response.data) {
        return response.data;
      }
      return null;
    } catch (error) {
      log(`CircleCi fetch error for ${cveId}: ${error.message}`, "WARN");
      return null;
    }
  }

  static extractScoreFromCircleCi(data) {
    try {
      // Try to get CVSS3 score first, fall back to CVSS2
      if (data.cvss3) {
        return parseFloat(data.cvss3);
      } else if (data.cvss) {
        return parseFloat(data.cvss);
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  static extractVectorFromCircleCi(data) {
    try {
      // Try to get CVSS3 vector first, fall back to CVSS2
      if (data.cvss3_vector) {
        return data.cvss3_vector;
      } else if (data.cvss_vector) {
        return data.cvss_vector;
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  static extractCwesFromCircleCi(data) {
    try {
      const cwes = [];
      
      // CircleCi API sometimes includes CWEs in references
      if (data.references) {
        for (const ref of data.references) {
          if (ref.toLowerCase().includes('cwe-')) {
            // Extract CWE-XXX pattern
            const match = ref.match(/CWE-\d+/i);
            if (match) cwes.push(match[0]);
          }
        }
      }

      // CircleCi may also have CWEs in capec field
      if (data.capec && Array.isArray(data.capec)) {
        for (const capec of data.capec) {
          if (capec.related_weakness && Array.isArray(capec.related_weakness)) {
            for (const cwe of capec.related_weakness) {
              if (cwe) cwes.push(`CWE-${cwe}`);
            }
          }
        }
      }

      return cwes.length > 0 ? cwes : null;
    } catch (error) {
      return null;
    }
  }

  // NVD API methods
  static async fetchFromNvd(cveId) {
    try {
      await this.throttleRequest('nvd');

      // Check if NVD API key is available (recommended for production)
      const headers = {};
      const nvd_token = `95d40afa-9118-4d88-bd1e-9e1c15d4c91d`;
      headers['apiKey'] = nvd_token;
      if (process.env.NVD_API_KEY) {
        headers['apiKey'] = process.env.NVD_API_KEY;
      }

      const response = await axios.get(this.APIs.nvd, {
        params: { cveId },
        headers,
        timeout: 10000
      });

      if (response.status === 200 && 
          response.data && 
          response.data.vulnerabilities && 
          response.data.vulnerabilities.length > 0) {
        return response.data.vulnerabilities[0].cve;
      }
      return null;
    } catch (error) {
      log(`NVD fetch error for ${cveId}: ${error.message}`, "WARN");
      return null;
    }
  }

  static extractScoreFromNvd(data) {
    try {
      if (!data.metrics) return null;

      // Try CVSS 3.1 first, then 3.0, then 2.0
      if (data.metrics.cvssMetricV31 && data.metrics.cvssMetricV31.length > 0) {
        return data.metrics.cvssMetricV31[0].cvssData.baseScore;
      } else if (data.metrics.cvssMetricV30 && data.metrics.cvssMetricV30.length > 0) {
        return data.metrics.cvssMetricV30[0].cvssData.baseScore;
      } else if (data.metrics.cvssMetricV2 && data.metrics.cvssMetricV2.length > 0) {
        return data.metrics.cvssMetricV2[0].cvssData.baseScore;
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  static extractVectorFromNvd(data) {
    try {
      if (!data.metrics) return null;

      // Try CVSS 3.1 first, then 3.0, then 2.0
      if (data.metrics.cvssMetricV31 && data.metrics.cvssMetricV31.length > 0) {
        return data.metrics.cvssMetricV31[0].cvssData.vectorString;
      } else if (data.metrics.cvssMetricV30 && data.metrics.cvssMetricV30.length > 0) {
        return data.metrics.cvssMetricV30[0].cvssData.vectorString;
      } else if (data.metrics.cvssMetricV2 && data.metrics.cvssMetricV2.length > 0) {
        return data.metrics.cvssMetricV2[0].cvssData.vectorString;
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  static extractCwesFromNvd(data) {
    try {
      const cwes = [];
      
      if (data.weaknesses && Array.isArray(data.weaknesses)) {
        for (const weakness of data.weaknesses) {
          if (weakness.description && Array.isArray(weakness.description)) {
            for (const desc of weakness.description) {
              if (desc.value && desc.value.startsWith('CWE-')) {
                cwes.push(desc.value);
              }
            }
          }
        }
      }
      
      return cwes.length > 0 ? cwes : null;
    } catch (error) {
      return null;
    }
  }
}

// Function to capture statistics about vulnerability data completeness
function getVulnerabilityStats(vulnerabilities) {
  const total = vulnerabilities.length;
  const withScore = vulnerabilities.filter(v => v.score !== null).length;
  const withVector = vulnerabilities.filter(v => v.cvssVector !== null).length;
  const withCwes = vulnerabilities.filter(v => v.cwes !== null && v.cwes.length > 0).length;
  const complete = vulnerabilities.filter(v => 
    v.score !== null && 
    v.cvssVector !== null && 
    v.cwes !== null && 
    v.cwes.length > 0
  ).length;
  
  const stats = {
    totalVulnerabilities: total,
    withScore,
    withVector,
    withCwes,
    complete,
    scorePercentage: total > 0 ? Math.round((withScore / total) * 100) : 0,
    vectorPercentage: total > 0 ? Math.round((withVector / total) * 100) : 0,
    cwesPercentage: total > 0 ? Math.round((withCwes / total) * 100) : 0,
    completePercentage: total > 0 ? Math.round((complete / total) * 100) : 0
  };
    return stats;
}

// Extract basic vulnerability data from Grype scan and enrich with external API data if needed
async function processVulnerability(vulnerability) {
  const { id, severity, description } = vulnerability;
  
  // Try to get data from Grype first
  let cvssScore = null;
  let cvssVector = null;
  let cwes = [];

  if (vulnerability.cvss && vulnerability.cvss.length > 0) {
    const latestCvss = vulnerability.cvss[vulnerability.cvss.length - 1];
    cvssScore = latestCvss?.metrics?.baseScore;
    cvssVector = latestCvss?.vector;
  }
  
  // Extract CWEs from Grype if available
  if (vulnerability.cwe && Array.isArray(vulnerability.cwe)) {
    cwes = [...vulnerability.cwe];
  } else if (vulnerability.related && Array.isArray(vulnerability.related.cwes)) {
    cwes = [...vulnerability.related.cwes];
  } else if (vulnerability.dataSource && vulnerability.dataSource.cwe) {
    if (Array.isArray(vulnerability.dataSource.cwe)) {
      cwes = [...vulnerability.dataSource.cwe];
    } else {
      cwes = [vulnerability.dataSource.cwe];
    }
  }
  
  // If we're missing any data, try to get it from external APIs
  if (!cvssScore || !cvssVector || cwes.length === 0) {
    const externalData = await CveInfoService.getCveInfo(id);
    if (externalData) {
      // Only use external data if we don't have it from Grype
      if (!cvssScore && externalData.score) cvssScore = externalData.score;
      if (!cvssVector && externalData.cvssVector) cvssVector = externalData.cvssVector;
      if (cwes.length === 0 && externalData.cwes) cwes = externalData.cwes;
    }
  }
  
  return {
    cveId: id,
    severity,
    description,
    score: cvssScore,
    cvssVector: cvssVector,
    cwes: cwes.length > 0 ? cwes : null,
  };
}

// Create a new function to process SonarQube issues like vulnerabilities
async function processSonarIssue(issue) {
  // Convert SonarQube issue to vulnerability format
  const vulnerability = {
    id: issue.key, // Use issue key as CVE-like ID
    severity: mapSonarSeverity(issue.severity),
    description: issue.message,
    // Initialize fields that will be enriched
    cvss: null,
    cwe: null
  };

  // Try to extract any CVE references from the issue
  let cveId = null;
  if (issue.message && issue.message.includes('CVE-')) {
    const cveMatch = issue.message.match(/CVE-\d{4}-\d{4,}/);
    if (cveMatch) {
      cveId = cveMatch[0];
    }
  }

  // If we found a CVE, try to get enriched data
  let cvssScore = null;
  let cvssVector = null;
  let cwes = [];

  if (cveId) {
    const externalData = await CveInfoService.getCveInfo(cveId);
    if (externalData) {
      cvssScore = externalData.score;
      cvssVector = externalData.cvssVector;
      cwes = externalData.cwes || [];
    }
  }

  // Extract any CWE info from tags
  if (issue.tags && Array.isArray(issue.tags)) {
    const cweFromTags = issue.tags.filter(tag => tag.startsWith('cwe') || tag.includes('cwe'));
    if (cweFromTags.length > 0) {
      cwes = [...cwes, ...cweFromTags];
    }
  }

  return {
    cveId: cveId || issue.rule, // Use CVE if found, otherwise use rule key
    severity: mapSonarSeverity(issue.severity),
    description: issue.message,
    score: cvssScore,
    cvssVector: cvssVector,
    cwes: cwes.length > 0 ? cwes : null,
  };
}

// Determine security state based on vulnerability severity levels
function determineSecurityState(vulnerabilities) {
  const criticals = vulnerabilities.filter((v) => v.severity === "Critical");
  const highs = vulnerabilities.filter((v) => v.severity === "High");

  let securityState = "S6";
  if (criticals.length === 0 && highs.length === 0) {
    securityState = "S3";
  } else if (criticals.length > 0) {
    securityState = "S5.2";
  } else if (highs.length > 0) {
    securityState = "S5.1*";
  }
  
  return securityState;
}

// Main function to process an image scan
async function processImageScan(name, scannerType = 'grype') {
  const uuid = randomUUID();
  log(`Received ${scannerType} scan request for image: ${name} (UUID: ${uuid})`);

  try {
    // Create scan directory and setup output path
    await mkdir("./scan-log", { recursive: true });
    const outputPath = `./scan-log/${uuid}.json`;
    
    // Step 1: Run the scan
    await new Promise((resolve, reject) => {
      const command = spawn("grype", [
        name,
        "-o",
        "json",
        "--by-cve",
        "--file",
        outputPath,
      ]);

      command.stdout.on("data", (data) => {
        log(`Grype: ${data}`);
      });

      command.stderr.on("data", (data) => {
        log(`Grype Error: ${data}`, "ERROR");
      });

      command.on("close", (code) => {
        log(`Grype process exited with code ${code}`);
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Grype exited with code ${code}`));
        }
      });
    });

    // Step 2: Read and parse scan results
    const data = await readFile(outputPath, "utf8");
    const output = JSON.parse(data);
    const { matches } = output;    // Step 3: Process and enrich vulnerabilities using adapter
    log(`Processing ${matches.length} vulnerabilities from Grype`);
    const vulnerabilities = await processResultWithAdapter({ matches }, 'grype');

    // Step 4: Generate statistics (for logging purposes)
    getVulnerabilityStats(vulnerabilities);
    
    // Step 5: Determine security state
    const securityState = determineSecurityState(vulnerabilities);

    // Clean up
    await unlink(outputPath);

    // Step 6: Send results
    const payload = {
      eventCode: "IMAGE_SCAN_COMPLETE",
      imageName: name,
      securityState,
      data: vulnerabilities
    };

    log(`Sent scan results to ${process.env.API_URL}/webhook/image`);
    await axios.post(`${process.env.API_URL}/webhook/image`, payload);

    return { success: true, requestId: uuid };
  } catch (error) {
    log(`Error during image scan: ${error.message}`, "ERROR");
    return { success: false, error: error.message, requestId: uuid };
  }
}

// ...existing code...
// ...existing code...

async function processCodeScan(name, url, version, scannerType = 'sonarqube') {
  const uuid = randomUUID();
  log(`Received ${scannerType} scan request for repo: ${name} (UUID: ${uuid})`);

  try {
    // 1. Clone or fetch the repo at the specified version (branch/tag/commit)
    const repoDir = `./scan-log/${uuid}-repo`;
    await mkdir(repoDir, { recursive: true });

    await new Promise((resolve, reject) => {
      const gitClone = spawn("git", ["clone", url, repoDir]);
      gitClone.on("close", (code) => {
        if (code === 0) {
          if (version) {
            // Checkout the specific version
            const gitCheckout = spawn("git", ["checkout", version], { cwd: repoDir });
            gitCheckout.on("close", (checkoutCode) => {
              if (checkoutCode === 0) resolve();
              else reject(new Error(`git checkout failed with code ${checkoutCode}`));
            });
          } else {
            resolve();
          }
        } else {
          reject(new Error(`git clone failed with code ${code}`));
        }
      });
    });

    // 2. Run SonarQube Scanner CLI
    const SONAR_HOST_URL = process.env.SONAR_HOST_URL;
    const SONAR_TOKEN = process.env.SONAR_TOKEN;
    const SONAR_ORGANIZATION = process.env.SONAR_ORGANIZATION;
    const projectKey = `scan-${name}-${version}`;
    
    await new Promise((resolve, reject) => {
      const scannerArgs = [
        `-Dsonar.projectKey=${projectKey}`,
        `-Dsonar.sources=.`,
        `-Dsonar.host.url=${SONAR_HOST_URL}`,
        `-Dsonar.token=${SONAR_TOKEN}`,
      ];

      // Add organization for SonarCloud
      if (SONAR_ORGANIZATION) {
        scannerArgs.push(`-Dsonar.organization=${SONAR_ORGANIZATION}`);
      }

      const scanner = spawn("sonar-scanner", scannerArgs, { cwd: repoDir });

      scanner.stdout.on("data", (data) => log(`SonarQube: ${data}`));
      scanner.stderr.on("data", (data) => log(`SonarQube Error: ${data}`, "ERROR"));
      scanner.on("close", (code) => {
        log(`SonarQube scanner exited with code ${code}`);
        if (code === 0) resolve();
        else reject(new Error(`SonarQube scanner failed with code ${code}`));
      });
    });    // 3. Fetch issues from SonarQube REST API
    log(`Fetching issues from SonarQube for project: ${projectKey}`);
    const issuesRes = await axios.get(
      `${SONAR_HOST_URL}/api/issues/search`,
      {
        params: {
          componentKeys: projectKey,
          types: "VULNERABILITY,BUG,CODE_SMELL",
          ps: 500, // page size
        },
        headers: {
          Authorization: `Bearer ${SONAR_TOKEN}`,
        },
      }
    );
    
    log(`SonarQube API Response Status: ${issuesRes.status}`);
    log(`SonarQube API Response Data:`, JSON.stringify(issuesRes.data, null, 2));
    
    const issues = issuesRes.data.issues || [];
    log(`Found ${issues.length} issues from SonarQube`);
    
    if (issues.length > 0) {
      log(`Sample issue:`, JSON.stringify(issues[0], null, 2));
    }    // 4. Process and format vulnerabilities (convert SonarQube issues to your format)
    log(`Processing ${issues.length} issues from SonarQube`);
    const vulnerabilities = await processResultWithAdapter({ issues }, 'sonarqube');// 5. Generate statistics (optional)
    const stats = getVulnerabilityStats(vulnerabilities);
    log(`Vulnerability statistics:`, JSON.stringify(stats, null, 2));

    // 6. Determine security state (reuse your logic)
    const securityState = determineSecurityState(vulnerabilities);
    log(`Determined security state: ${securityState}`);

    // Log processed vulnerabilities
    log(`Processed ${vulnerabilities.length} vulnerabilities:`);
    vulnerabilities.forEach((vuln, index) => {
      log(`Vulnerability ${index + 1}: ${vuln.cveId} (${vuln.severity}) - ${vuln.description?.substring(0, 100)}...`);
    });

    // 7. Clean up (optional: remove repoDir if you want)
    // await fs.rm(repoDir, { recursive: true, force: true });

    // 8. Send results (optional, like image scan)
    const payload = {
      eventCode: "CODE_SCAN_COMPLETE",
      imageName: name + ":" + version,
      securityState,
      data: vulnerabilities,
    };

    log(`Sending payload to ${process.env.API_URL}/webhook/code:`, JSON.stringify(payload, null, 2));
    await axios.post(`${process.env.API_URL}/webhook/code`, payload);
    log(`Successfully sent code scan results to webhook`);

    return { success: true, requestId: uuid };
  } catch (error) {
    log(`Error during code scan: ${error.message}`, "ERROR");
    return { success: false, error: error.message, requestId: uuid };
  }
}

// Helper function to map SonarQube severity to your format
function mapSonarSeverity(sonarSeverity) {
  const severityMap = {
    'BLOCKER': 'Critical',
    'CRITICAL': 'Critical', 
    'MAJOR': 'High',
    'MINOR': 'Medium',
    'INFO': 'Low'
  };
  return severityMap[sonarSeverity] || 'Unknown';
}

// ...existing code...

// ...existing code...

app.get("/scan", async (req, res) => {
  try {
    const { name, scannerType = 'grype' } = req.query;
    if (!name) {
      return res.status(400).json({ error: "Missing image name" });
    }

    log(`Starting ${scannerType} scan for image: ${name}`);
    const result = await processImageScan(name, scannerType);
    if (result.success) {
      res.json({ 
        message: `Scanning artifact ${name} with ${scannerType}...`, 
        requestId: result.requestId 
      });
    } else {
      res.status(500).json({ error: result.error, requestId: result.requestId });
    }
  } catch (error) {
    log(`Error processing request: ${error.message}`, "ERROR");
    res.status(500).json({ error: "Internal server error" });
  }
});


// Add the new API endpoint
app.get("/scan/code", async (req, res) => {
  try {
    const { name, url, version, scannerType = 'sonarqube' } = req.query;
    if (!name || !url) {
      return res.status(400).json({ error: "Missing name or url" });
    }

    log(`Starting ${scannerType} code scan for: ${name}`);
    const result = await processCodeScan(name, url, version, scannerType);
    if (result.success) {
      res.json({
        message: `Scanning code repository ${name} with ${scannerType}...`,
        requestId: result.requestId,
      });
    } else {
      res.status(500).json({ error: result.error, requestId: result.requestId });
    }
  } catch (error) {
    log(`Error processing code scan request: ${error.message}`, "ERROR");
    res.status(500).json({ error: "Internal server error" });
  }
});


app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  log(`Image scanning service running on port ${port}`);
});