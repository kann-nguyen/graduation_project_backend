const axios = require('axios');
const fs = require('fs').promises;
const fileTypeFromBuffer = require('file-type').fromBuffer;
const { exec } = require('child_process');
const express = require('express');
const tmp = require('tmp');
const winston = require('winston');

const app = express();
app.use(express.json());

// Logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()]
});

app.post('/docs', async (req, res) => {
  const { artifact } = req.body;

  if (!artifact || !artifact.url) {
    return res.status(400).send({ error: 'Artifact URL is required.' });
  }

  try {
    const state = await validateAndScanDocument(artifact);
    res.status(200).send({ state });
  } catch (error) {
    logger.error("[ERROR] Scanning failed:", error);
    res.status(500).send({ error: 'Scanning failed' });
  }
});

app.listen(4000, () => {
  logger.info("Document scanning service is running on port 4000");
});

async function downloadFile(url) {
  try {
    const response = await axios.get(url, { responseType: 'arraybuffer' });
    const buffer = Buffer.from(response.data);
    return buffer;
  } catch (error) {
    logger.error("Error downloading file:", error);
    return null;
  }
}

async function checkFileType(buffer) {
  const type = await fileTypeFromBuffer(buffer);
  return type ? type.ext : 'unknown';
}

async function scanWithTool(command) {
  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        logger.error(`[ERROR] Command failed: ${command}`, stderr);
        return reject(stderr);
      }
      resolve(stdout);
    });
  });
}

async function scanForSensitiveData(filePath) {
  try {
    const [trufflehogOutput, gitleaksOutput] = await Promise.all([
      scanWithTool(`trufflehog --regex --entropy=False --max_depth=5 ${filePath}`),
      scanWithTool(`gitleaks detect --source=${filePath} --no-banner`)
    ]);
    return trufflehogOutput.includes('No secrets found') && gitleaksOutput.includes('No leaks found') ? false : true;
  } catch (error) {
    logger.error("[ERROR] Scanning failed:", error);
    return true;
  }
}

async function checkPolicyCompliance(content) {
  const compliancePolicyKeywords = ['confidential', 'internal use only', 'sensitive'];
  return !compliancePolicyKeywords.some(keyword => content.includes(keyword));
}

async function validateAndScanDocument(artifact) {
  logger.info(`[INFO] Processing document: ${artifact._id}`);
  const fileBuffer = await downloadFile(artifact.url);
  if (!fileBuffer) return '[ERROR] Failed to download file';

  const fileTypeExt = await checkFileType(fileBuffer);
  if (!['pdf', 'docx', 'txt'].includes(fileTypeExt)) return 'S1';

  const tmpFile = tmp.fileSync({ postfix: `.${fileTypeExt}` });
  await fs.writeFile(tmpFile.name, fileBuffer);

  const sensitiveDataFound = await scanForSensitiveData(tmpFile.name);
  const fileContent = await fs.readFile(tmpFile.name, 'utf8');
  const isCompliant = await checkPolicyCompliance(fileContent);

  tmpFile.removeCallback();
  return sensitiveDataFound || !isCompliant ? 'S1' : 'S2';
}