import express from 'express';
import { randomUUID } from 'crypto';
import 'dotenv/config';
import { mkdir, readFile, unlink } from 'fs/promises';
import axios from 'axios';
import { spawn } from 'child_process';

const app = express();
const port = 5000;

// Utility: Log with timestamp
function log(message, type = 'INFO') {
  console.log(`[${new Date().toISOString()}] [${type}] ${message}`);
}

// Function to run security scans (e.g., SonarQube, Semgrep, etc.)
const runSourceScan = async (repoUrl, uuid) => {
  return new Promise((resolve, reject) => {
    const outputPath = `./scan-log/${uuid}.json`;

    // Run multiple tools to scan source code
    const command = spawn('sh', [
      '-c',
      `sonar-scanner -Dsonar.projectBaseDir=${repoUrl} && semgrep --config auto ${repoUrl} && codeql database analyze ${repoUrl} -o ${outputPath}`,
    ]);

    command.stdout.on('data', (data) => {
      log(`Source scan: ${data}`);
    });

    command.stderr.on('data', (data) => {
      log(`Source scan Error: ${data}`, 'ERROR');
    });

    command.on('close', (code) => {
      log(`Source scan process exited with code ${code}`);
      if (code === 0) {
        resolve(outputPath);
      } else {
        reject(new Error(`Source scan exited with code ${code}`));
      }
    });
  });
};

// Function to extract and send scan results
const handleScanResult = async (filePath, repoUrl) => {
  const data = await readFile(filePath, 'utf8');
  const output = JSON.parse(data);
  const vulnerabilities = output.issues || [];  // Adapt to how the output of the scanners is structured

  const securityState = determineSecurityState(vulnerabilities);
  console.log(`[+] Security state for repository '${repoUrl}': ${securityState}`);

  await unlink(filePath);
  log(`Deleted scan log: ${filePath}`);

  const payload = {
    eventCode: 'SOURCE_SCAN_COMPLETE',
    repoUrl,
    securityState,
    data: vulnerabilities,
  };

  console.log('[+] Webhook sent successfully.');

  await axios.post(`${process.env.API_URL}/webhook/source`, payload);
  log(`Sent scan results to ${process.env.API_URL}/webhook/source`);
};

// Route to scan source code repository
app.post('/source', async (req, res) => {
  const { repoUrl } = req.query;
  if (!repoUrl) {
    log('Missing repository URL in query', 'WARN');
    return res.status(400).json({ error: 'Missing repository URL' });
  }

  const uuid = randomUUID();
  log(`Received scan request for repository: ${repoUrl} (UUID: ${uuid})`);

  res.json({ message: `Scanning repository ${repoUrl}`, requestId: uuid });

  try {
    // Create a folder if it doesn't exist
    await mkdir('./scan-log', { recursive: true });
  } catch (error) {
    log(`Error creating scan log directory: ${error.message}`, 'ERROR');
  }

  try {
    log(`Start scan for repository: ${repoUrl} (UUID: ${uuid})`);
    const filePath = await runSourceScan(repoUrl, uuid);
    log(`Start handling result for repository: ${repoUrl} (UUID: ${uuid})`);
    await handleScanResult(filePath, repoUrl);
  } catch (error) {
    log(`Error during source scan: ${error.message}`, 'ERROR');
  }
});

// Determine security state based on vulnerabilities
function determineSecurityState(vulnerabilities) {
  const criticals = vulnerabilities.filter((v) => v.severity === 'Critical');
  const highs = vulnerabilities.filter((v) => v.severity === 'High');

  if (criticals.length === 0 && highs.length === 0) {
    return 'S3'; // Ready to deploy
  }

  if (criticals.length > 0) {
    return 'S5.2'; // Partially Compromised
  }

  if (highs.length > 0) {
    return 'S5.1*'; // Threatened
  }

  return 'S6'; // Protecting - fallback
}

// Health check route
app.get('/', (req, res) => {
  res.send('Source scanning service is running!');
});

app.listen(port, () => {
  log(`Source scanning service running on port ${port}`);
});
