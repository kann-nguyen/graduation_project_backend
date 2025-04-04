import axios from 'axios';
import express from 'express';
import { exec } from 'child_process';

// Initialize Express app
const app = express();
app.use(express.json());

// Endpoint to scan Docker image
app.post('/scan-image', async (req, res) => {
  const { image } = req.body;
  
  if (!image || !image.repoUrl || !image.digest) {
    return res.status(400).send({ error: 'Repository URL and Digest are required.' });
  }

  try {
    const state = await validateAndScanImage(image);
    res.status(200).send({ state });
  } catch (error) {
    console.error("[ERROR] Scanning failed:", error);
    res.status(500).send({ error: 'Scanning failed' });
  }
});

app.listen(6000, () => {
  console.log("Docker image scanning service is running on port 5000");
});

// Function to validate and scan the Docker image
async function validateAndScanImage(image) {
  console.log(`[INFO] Validating Docker image: ${image.repoUrl}`);
  const integrityValid = await validateImageIntegrity(image);
  if (!integrityValid) return 'S1'; // Stay at S1 if integrity check fails

  console.log("[INFO] Running security scans...");
  const hasVulnerabilities = await runSecurityScans(image.repoUrl);
  const isSignatureValid = await verifyImageSignature(image.repoUrl);

  let state = 'S3';
  if (hasVulnerabilities || !isSignatureValid) {
    state = 'S1'; // Stay at S1 if vulnerabilities or invalid signature
  } else {
    // If signature is valid and no vulnerabilities found, move to S4
    const deployable = await checkDeploymentReadiness(image.repoUrl);
    if (deployable) {
      state = 'S4'; // If deployable, transition to S4
    }
  }

  console.log(`[INFO] Image state: ${state}`);
  return state;
}

// Function to validate image integrity by checking digest
async function validateImageIntegrity(image) {
  try {
    console.log("[INFO] Checking image digest...");
    const response = await axios.get(`${image.repoUrl}/v2/${image.digest}`);
    return response.status === 200;
  } catch (error) {
    console.error("[ERROR] Image integrity validation failed:", error);
    return false;
  }
}

// Function to run security scans (Trivy, Clair, or Grype)
async function runSecurityScans(repoUrl) {
  return new Promise((resolve) => {
    exec(`trivy image ${repoUrl} && grype ${repoUrl}`, (error, stdout, stderr) => {
      if (error || stderr) {
        console.error("[ERROR] Security scan found vulnerabilities:", stderr);
        resolve(true); // Vulnerabilities found
      } else {
        console.log("[INFO] Security scan passed.");
        resolve(false); // No vulnerabilities
      }
    });
  });
}

// Function to verify image signature (Cosign or Notary)
async function verifyImageSignature(repoUrl) {
  return new Promise((resolve) => {
    exec(`cosign verify ${repoUrl}`, (error, stdout, stderr) => {
      if (error || stderr.includes('failed')) {
        console.error("[ERROR] Image signature verification failed:", stderr);
        resolve(false); // Signature invalid
      } else {
        console.log("[INFO] Image signature is valid.");
        resolve(true); // Signature valid
      }
    });
  });
}

// Function to check if the image is ready to deploy (using Kube-bench or similar tools)
async function checkDeploymentReadiness(repoUrl) {
  return new Promise((resolve) => {
    exec(`kube-bench --version ${repoUrl}`, (error, stdout, stderr) => {
      if (error || stderr) {
        console.error("[ERROR] Image deployment check failed:", stderr);
        resolve(false); // Deployment failed
      } else {
        console.log("[INFO] Image is ready for deployment.");
        resolve(true); // Deployment check passed
      }
    });
  });
}
