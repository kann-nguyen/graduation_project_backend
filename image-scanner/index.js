import express from "express";
import { spawn } from "child_process";
import { randomUUID } from "crypto";
import "dotenv/config";
import { mkdir, readFile, unlink } from "fs/promises";
import axios from "axios";

const app = express();
const port = 3000;

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

async function processImageScan(name) {
  const uuid = randomUUID();
  log(`Received scan request for image: ${name} (UUID: ${uuid})`);

  try {
    await mkdir("./scan-log", { recursive: true });
    const outputPath = `./scan-log/${uuid}.json`;
    
    // Run Grype scan
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

    // Process scan results
    const data = await readFile(outputPath, "utf8");
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

    console.log(`[+] Security state for image '${name}': ${securityState}`);

    await unlink(outputPath);
    log(`Deleted scan log: ${outputPath}`);

    const payload = {
      eventCode: "IMAGE_SCAN_COMPLETE",
      imageName: name,
      securityState,
      data: vulnerabilities
    };

    await axios.post(`${process.env.API_URL}/webhook/image`, payload);
    log(`Sent scan results to ${process.env.API_URL}/webhook/image`);

    return { success: true, requestId: uuid };
  } catch (error) {
    log(`Error during image scan: ${error.message}`, "ERROR");
    return { success: false, error: error.message, requestId: uuid };
  }
}

app.get("/scan", async (req, res) => {
  try {
    const { name } = req.query;
    if (!name) {
      log("Missing image name in query", "WARN");
      return res.status(400).json({ error: "Missing image name" });
    }

    const result = await processImageScan(name);
    if (result.success) {
      res.json({ 
        message: `Scanning artifact ${name}...`, 
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

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  log(`Image scanning service running on port ${port}`);
});