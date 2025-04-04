import axios from 'axios';
import express from 'express';
import { exec } from 'child_process';

// Mã nguồn của bạn ở đây

const app = express();
app.use(express.json());

// Endpoint to scan source code repository
app.post('/scan-source', async (req, res) => {
  const { artifact } = req.body;
  
  if (!artifact || !artifact.repoUrl) {
    return res.status(400).send({ error: 'Repository URL is required.' });
  }

  try {
    const state = await validateAndScanSourceCode(artifact);
    res.status(200).send({ state });
  } catch (error) {
    console.error("[ERROR] Scanning failed:", error);
    res.status(500).send({ error: 'Scanning failed' });
  }
});

app.listen(5000, () => {
  console.log("Source code scanning service is running on port 5000");
});

// Function to validate and scan source code
async function validateAndScanSourceCode(artifact) {
  console.log(`[INFO] Validating repository: ${artifact.repoUrl}`);
  const repoValid = await validateRepository(artifact.repoUrl);
  if (!repoValid) return 'S1';

  console.log("[INFO] Running security scans...");
  const hasVulnerabilities = await runSecurityScans(artifact.repoUrl);
  const hasSecrets = await scanForSecrets(artifact.repoUrl);

  let state = 'S2';
  if (hasVulnerabilities || hasSecrets) {
    state = 'S1';
  }

  console.log(`[INFO] Assigning security state: ${state}`);
  return state;
}

// Function to validate the repository (GitHub, GitLab, etc.)
async function validateRepository(repoUrl) {
  try {
    const response = await axios.get(`${repoUrl}/branches`);
    return response.status === 200;
  } catch (error) {
    console.error("[ERROR] Invalid repository:", error);
    return false;
  }
}

// Function to run SonarQube, Semgrep, and CodeQL scans
async function runSecurityScans(repoUrl) {
  return new Promise((resolve) => {
    exec(`sonar-scanner -Dsonar.projectBaseDir=${repoUrl} && semgrep --config auto ${repoUrl} && codeql database analyze ${repoUrl}`,
      (error, stdout, stderr) => {
        if (error || stderr.includes("CRITICAL")) {
          console.error("[ERROR] Security scan detected vulnerabilities:", stderr);
          resolve(true);
        } else {
          console.log("[INFO] Security scan passed.");
          resolve(false);
        }
      }
    );
  });
}

// Function to scan for hardcoded secrets using Gitleaks & TruffleHog
async function scanForSecrets(repoUrl) {
  return new Promise((resolve) => {
    exec(`gitleaks detect --source=${repoUrl} && trufflehog ${repoUrl}`,
      (error, stdout, stderr) => {
        if (error || stdout.includes("Secret found")) {
          console.error("[ERROR] Hardcoded secrets detected:", stdout);
          resolve(true);
        } else {
          console.log("[INFO] No secrets detected.");
          resolve(false);
        }
      }
    );
  });
}
