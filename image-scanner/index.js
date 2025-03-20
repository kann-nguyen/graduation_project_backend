import express from "express";
import { spawn } from "child_process";
import { randomUUID } from "crypto";
import "dotenv/config";
import { mkdir, readFile, unlink } from "fs/promises";
import axios from "axios";
const app = express();
const port = 3000;
app.get("/image", async (req, res) => {
  const { name } = req.query; // Example: name=alpine:3.12
  if (!name) {
    return res.status(400).json({ error: "Missing image name" });
  }
  const uuid = randomUUID();
  res.json({ message: `Scanning image ${name}` });
  try {
    // Create a folder if it doesn't exist
    await mkdir("./scan-log", { recursive: true });
  } catch (error) {
    console.log(error);
  }
  const command = spawn("grype", [
    name,
    "-o",
    "json",
    "--by-cve",
    "--file",
    `./scan-log/${uuid}.json`,
  ]);
  command.stdout.on("data", (data) => {
    console.log(`Received data: ${data}`);
  });
  command.on("close", async (code) => {
    console.log(`Child process exited with code ${code}`);
    // Process the output log
    try {
      const data = await readFile(`./scan-log/${uuid}.json`, "utf8");
      const output = JSON.parse(data);
      const { matches } = output;
      const vulnerabilities = matches.map((match) => {
        const { vulnerability } = match;
        const { id, severity, description, cvss } = vulnerability;
        const cvssScore = cvss[cvss.length - 1]?.metrics.baseScore;
        return { cveId: id, severity, description, score: cvssScore };
      });
      // Delete the log file
      await unlink(`./scan-log/${uuid}.json`);
      // Send data to backend
      await axios.post(`${process.env.API_URL}/webhook/image`, {
        eventCode: "IMAGE_SCAN_COMPLETE",
        imageName: name,
        data: vulnerabilities,
      });
    } catch (error) {
      console.log(error);
    }
  });
});

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  console.log(`Image scanning service running on port ${port}`);
});
