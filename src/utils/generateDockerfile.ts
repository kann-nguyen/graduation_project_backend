import { Configuration } from "../models/scanner";
import * as fs from "fs/promises";
export async function generateDockerfile(config: Configuration) {
  // Read the Dockerfile template
  let dockerfile = await fs.readFile(
    "./src/utils/Dockerfile.template",
    "utf-8"
  );
  const { installCommand, code } = config;
  // Replace install command
  dockerfile = dockerfile.replace(/<install_command>/g, installCommand);
  // Trim all the newlines in the code
  const escapedCode = code
    .replace(/\\/g, '\\\\')     // Escape backslashes first
    .replace(/'/g, "\\'")       // Escape single quotes
    .replace(/"/g, '\\"')       // Escape double quotes
    .replace(/`/g, '\\`')       // Escape backticks
    .replace(/\$/g, '\\$')      // Escape dollar signs for template literals
    .replace(/\n/g, '\\n');     // Replace newlines with \n
  dockerfile = dockerfile.replace(/<code_content>/g, escapedCode);
  return dockerfile;
}
const vulnInterface = `interface Vulnerability {
  cveId: string;
  description: string;
  score: number | null;
  severity: string;
  cvssVector: string | null;
  cwes: string[] | null;
}`;
const sampleCode = `async function processImageScan(name) {
  const uuid = randomUUID();
  log(\`[SCAN-START] Received scan request for image: \${name} (UUID: \${uuid})\`);
  
  try {
    log(\`[SCAN-SETUP] Creating scan directory for image: \${name}\`);
    await mkdir("./scan-log", { recursive: true });
    const outputPath = \`./scan-log/\${uuid}.json\`;
    log(\`[SCAN-SETUP] Output file will be: \${outputPath}\`);
    
    log(\`[SCAN-PROCESS] Starting Trivy scan for image: \${name}...\`);
    await new Promise((resolve, reject) => {
      const trivyArgs = [
        "image",
        \`\${name}\`,
        "--scanners", "vuln",
        "--format", "json",
        "--output", outputPath
      ];
      log(\`[SCAN-COMMAND] Running: trivy \${trivyArgs.join(" ")}\`);
      
      const command = spawn("trivy", trivyArgs);
      
      command.stdout.on("data", (data) => {
        const output = data.toString().trim();
        if (output) {
          log(\`[SCAN-OUTPUT] Trivy: \${output}\`);
        }
      });
      
      command.stderr.on("data", (data) => {
        const error = data.toString().trim();
        if (error) {
          log(\`[SCAN-ERROR] Trivy Error: \${error}\`, "ERROR");
        }
      });
      
      command.on("close", (code) => {
        log(\`[SCAN-COMPLETE] Trivy process exited with code \${code}\`);
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(\`Trivy exited with code \${code}\`));
        }
      });
    });
    
    log(\`[SCAN-PROCESSING] Reading scan results from \${outputPath}\`);
    const data = await readFile(outputPath, "utf8");
    log(\`[SCAN-DATA] File size: \${data.length} bytes\`);
    
    log(\`[SCAN-PARSING] Parsing JSON results\`);
    const json = JSON.parse(data);
    let vulnerabilities = [];
    
    if (json.Results) {
      log(\`[SCAN-RESULTS] Found \${json.Results.length} result groups\`);
      for (const result of json.Results) {
        log(\`[SCAN-RESULTS] Processing result for target: \${result.Target || 'unknown'}\`);
        if (result.Vulnerabilities) {
          log(\`[SCAN-VULNERABILITIES] Found \${result.Vulnerabilities.length} vulnerabilities for target: \${result.Target || 'unknown'}\`);
          const vulns = await Promise.all(result.Vulnerabilities.map(async (vuln) => {
            log(\`[SCAN-VULNERABILITY] Processing: \${vuln.VulnerabilityID} (Severity: \${vuln.Severity})\`);
            const vulnerability = {
              id: vuln.VulnerabilityID,
              severity: vuln.Severity,
              description: vuln.Description,
              cvss: vuln.CVSS ? [
                {
                  metrics: {
                    baseScore: vuln.CVSS?.nvd?.V3Score || null
                  },
                  vector: vuln.CVSS?.nvd?.V3Vector || null
                }
              ] : [],
              cwe: vuln.CweIDs || []
            };
            
            return processVulnerability(vulnerability);
          }));
          
          log(\`[SCAN-PROCESSING] Added \${vulns.length} processed vulnerabilities\`);
          vulnerabilities = [...vulnerabilities, ...vulns];
        } else {
          log(\`[SCAN-RESULTS] No vulnerabilities found for target: \${result.Target || 'unknown'}\`);
        }
      }
    } else {
      log(\`[SCAN-RESULTS] No results found in the scan output\`);
    }    
    log(\`[SCAN-STATS] Generating vulnerability statistics\`);
    getVulnerabilityStats(vulnerabilities);
    
    log(\`[SCAN-SECURITY] Determining security state for \${vulnerabilities.length} vulnerabilities\`);
    const securityState = determineSecurityState(vulnerabilities);
    log(\`[SCAN-SECURITY] Security state determined: \${securityState}\`);
    
    log(\`[SCAN-CLEANUP] Removing temporary scan file: \${outputPath}\`);
    await unlink(outputPath);
    
    const payload = {
      eventCode: "IMAGE_SCAN_COMPLETE",
      imageName: name,
      securityState,
      data: vulnerabilities
    };
    
    log(\`[SCAN-WEBHOOK] Preparing to send \${vulnerabilities.length} vulnerabilities to \${process.env.API_URL}/webhook/image\`);
    log(\`[SCAN-WEBHOOK] Sending scan results to \${process.env.API_URL}/webhook/image\`);
    
    try {
      log(\`[SCAN-DEBUG] Webhook payload size: \${JSON.stringify(payload).length} bytes\`);
      const response = await axios.post(\`\${process.env.API_URL}/webhook/image\`, payload);
      log(\`[SCAN-WEBHOOK] Webhook response status: \${response.status}\`);
    } catch (webhookError) {
      log(\`[SCAN-WEBHOOK] Error sending webhook: \${webhookError.message}\`, "ERROR");
      if (webhookError.response) {
        log(\`[SCAN-WEBHOOK] Response status: \${webhookError.response.status}\`, "ERROR");
      }
    }
    
    log(\`[SCAN-COMPLETE] Scan completed successfully for image: \${name} (UUID: \${uuid})\`);
    return { success: true, requestId: uuid };
  } catch (error) {
    log(\`[SCAN-ERROR] Error during image scan: \${error.message}\`, "ERROR");
    
    // Log more detailed error information if available
    if (error.stack) {
      log(\`[SCAN-ERROR] Stack trace: \${error.stack}\`, "ERROR");
    }
    
    return { success: false, error: error.message, requestId: uuid };
  }
}`;

export { vulnInterface, sampleCode };
