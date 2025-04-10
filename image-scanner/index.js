import express from "express";
import { spawn } from "child_process";
import { randomUUID } from "crypto";
import "dotenv/config";
import { mkdir, readFile, unlink } from "fs/promises";
import axios from "axios";

const app = express();
const port = 3000;

// Utility: Log with timestamp
function log(message, type = "INFO") {
  console.log(`[${new Date().toISOString()}] [${type}] ${message}`);
}

// Function to run Grype scan
const runGrypeScan = async (name, uuid) => {
  return new Promise((resolve, reject) => {
    const outputPath = `./scan-log/${uuid}.json`;
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
        resolve(outputPath);
      } else {
        reject(new Error(`Grype exited with code ${code}`));
      }
    });
  });
};

// Function to extract and send scan results
const handleScanResult = async (filePath, name) => {
  const data = await readFile(filePath, "utf8");
  const output = JSON.parse(data);
  const { matches } = output;

  const vulnerabilities = matches.map((match) => {
    const { vulnerability } = match;
    const { id, severity, description, cvss } = vulnerability;
    const cvssScore = cvss[cvss.length - 1]?.metrics?.baseScore ?? null;
    return {
      cveId: id,
      severity,
      description,
      score: cvssScore,
    };
  });

  // Determine security state
  const securityState = determineSecurityState(vulnerabilities);
  console.log(`[+] Security state for image '${name}': ${securityState}`);

  await unlink(filePath);
  log(`Deleted scan log: ${filePath}`);

  const payload = {
    eventCode: "IMAGE_SCAN_COMPLETE",
    imageName: name,
    securityState,
    data: vulnerabilities,
  };

  console.log("[+] Webhook sent successfully.");

  await axios.post(`${process.env.API_URL}/webhook/image`, payload);
  log(`Sent scan results to ${process.env.API_URL}/webhook/image`);
};

// Route to scan Docker image
app.get("/image", async (req, res) => {
  const { name } = req.query;
  if (!name) {
    log("Missing image name in query", "WARN");
    return res.status(400).json({ error: "Missing image name" });
  }

  const uuid = randomUUID();
  log(`Received scan request for image: ${name} (UUID: ${uuid})`);

  res.json({ message: `Scanning image ${name}`, requestId: uuid });

  try {
    // Create a folder if it doesn't exist
    await mkdir("./scan-log", { recursive: true });
  } catch (error) {
    console.log(error);
  }

  try {
    log(`Start scan image: ${name} (UUID: ${uuid})`);
    const filePath = await runGrypeScan(name, uuid);
    log(`Start handle result image: ${name} (UUID: ${uuid})`);
    await handleScanResult(filePath, name);
  } catch (error) {
    log(`Error during image scan: ${error.message}`, "ERROR");
  }
});

function determineSecurityState(vulnerabilities) {
  const criticals = vulnerabilities.filter((v) => v.severity === "Critical");
  const highs = vulnerabilities.filter((v) => v.severity === "High");

  if (criticals.length === 0 && highs.length === 0) {
    return "S3"; // Ready to deploy
  }

  if (criticals.length > 0) {
    return "S5.2"; // Partially Compromised
  }

  if (highs.length > 0) {
    return "S5.1*"; // Threatened
  }

  return "S6"; // Protecting - fallback
}

// Health check route
app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  log(`Image scanning service running on port ${port}`);
});
