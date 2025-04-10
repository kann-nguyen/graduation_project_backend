const express = require("express");
const axios = require("axios");
const fs = require("fs").promises;
const { exec } = require("child_process");
const tmp = require("tmp");
const { fromBuffer } = require("file-type");
require("dotenv").config();

const app = express();
app.use(express.json());
const PORT = 4000;

// Logger
function log(message, type = "INFO") {
  console.log(`[${new Date().toISOString()}] [${type}] ${message}`);
}

app.post("/docs", async (req, res) => {
  const artifact = req.body.artifact;

  if (!artifact || !artifact.url) {
    log("Missing artifact or artifact.url", "WARN");
    return res.status(400).json({ error: "Artifact URL is required" });
  }

  try {
    log(`Received scan request for doc: ${artifact._id}`);
    const result = await validateAndScanDocument(artifact);

    const payload = {
      eventCode: "DOC_SCAN_COMPLETE",
      artifactId: artifact._id,
      securityState: result.securityState,
      data: {
        hasSensitiveData: result.hasSensitiveData,
        policyCompliant: result.policyCompliant,
      },
    };

    if (process.env.API_URL) {
      await axios.post(`${process.env.API_URL}/webhook/docs`, payload);
      log(`Sent webhook to ${process.env.API_URL}/webhook/docs`);
    }

    return res.status(200).json({ state: result.securityState });
  } catch (err) {
    log(`Scan failed: ${err.message}`, "ERROR");
    return res.status(500).json({ error: "Scanning failed" });
  }
});

async function validateAndScanDocument(artifact) {
  log(`Downloading file from: ${artifact.url}`);
  const buffer = await downloadFile(artifact.url);
if (!buffer) {
  throw new Error("Failed to download file");
}

console.log("File downloaded successfully, buffer size:", buffer.length);

// Kiểm tra kết quả từ fromBuffer
const fileType = await fromBuffer(buffer);

const ext = fileType?.ext || "txt";
console.log("Final file extension:", ext);

if (!["pdf", "docx", "txt"].includes(ext)) {
  log(`Unsupported file type: ${ext}`, "WARN");
  return { securityState: "S1", hasSensitiveData: false, policyCompliant: true };
}

  const tmpFile = tmp.fileSync({ postfix: `.${ext}` });
  await fs.writeFile(tmpFile.name, buffer);


  const fileContent = await fs.readFile(tmpFile.name, "utf8").catch(() => "");
  log(`Check policy compliance : ${fileContent}`, "INFO");
  const policyCompliant = checkPolicyCompliance(fileContent);
  log(`Scan for sentitive data: ${tmpFile.name}`, "INFO");
  const hasSecrets = await scanForSensitiveData(tmpFile.name);

  tmpFile.removeCallback();

  const securityState = determineSecurityState(hasSecrets, policyCompliant);
  log(`Security state for doc '${artifact._id}': ${securityState}`);

  return { securityState, hasSensitiveData: hasSecrets, policyCompliant };
}

function determineSecurityState(hasSecrets, policyCompliant) {
  if (hasSecrets || !policyCompliant) return "S1";
  return "S2";
}

async function downloadFile(url) {
  try {
    const response = await axios.get(url, { responseType: "arraybuffer" });
    return Buffer.from(response.data);
  } catch (err) {
    log(`Download error: ${err.message}`, "ERROR");
    return null;
  }
}

function scanWithTool(command) {
  return new Promise((resolve, reject) => {
    exec(command, (err, stdout, stderr) => {
      if (err) {
        log(`Tool error: ${stderr}`, "ERROR");
        return reject(stderr);
      }
      resolve(stdout);
    });
  });
}

async function scanForSensitiveData(filePath) {
  try {
    const [trufflehog, gitleaks] = await Promise.all([
      scanWithTool(`trufflehog --regex --entropy=False --max_depth=5 ${filePath}`),
    ]);

    return !(trufflehog.includes("No secrets found") && gitleaks.includes("No leaks found"));
  } catch {
    return true; // Assume sensitive data if scan fails
  }
}

function checkPolicyCompliance(content) {
  const keywords = ["confidential", "internal use only", "sensitive"];
  return !keywords.some((k) => content.toLowerCase().includes(k));
}

// Health check
app.get("/", (_, res) => {
  res.send("Docs scanner is running");
});

app.listen(PORT, () => {
  log(`Docs scanner running on port ${PORT}`);
});
