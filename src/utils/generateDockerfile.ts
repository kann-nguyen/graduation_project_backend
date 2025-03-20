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
  const trimmedCode = code.replace(/\n/g, "");
  dockerfile = dockerfile.replace(/<code_content>/g, trimmedCode);
  return dockerfile;
}
const vulnInterface = `interface Vulnerability {
  cveId: string;
  description: string;
  score: number;
  severity: string;
  cwes: string[];
}`;
const sampleCode = `async function processImageScan(name) {
  const cmd = \`trivy image docker.io/\${name} --scanners vuln --format json --quiet\`;
  const command = spawnSync(cmd, { shell: true });
  const data = command.stdout.toString();
  const validJson = replaceUnicodeEscapeSequences(data);
  try {
    const json = JSON.parse(validJson);
    let response = [];
    json.Results.forEach((res) => {
      const vulnList = res.Vulnerabilities;
      const processed = vulnList?.map((x) => {
        const cveId = x?.VulnerabilityID;
        const severity = x?.Severity;
        const description = x?.Description;
        const score = x?.CVSS?.nvd?.V3Score;
        const cwes = x?.CweIDs;
        return { cveId, severity, description, score, cwes };
      });
      response.push(processed);
    });
    response = response.flat();
    await axios.post(\`https://dashboard-api.up.railway.app/webhook/image\`, {
      eventCode: \`IMAGE_SCAN_COMPLETE\`,
      imageName: name,
      data: response,
    });
  } catch (err) {
    fastify.log.error(err);
  }
}`;

export { vulnInterface, sampleCode };
