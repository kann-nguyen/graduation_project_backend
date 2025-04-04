import { Request, Response } from "express";
import { ArtifactModel, ChangeHistoryModel, ScannerModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import {
  generateDockerfile,
  sampleCode,
  vulnInterface,
} from "../utils/generateDockerfile";
import axios from 'axios';
import { Artifact } from "../models/artifact";
import { importGithubScanResult, importGitlabScanResult } from "../utils/vuln";
import { Types } from "mongoose";


// Get all scanners, optionally filtering by createdBy
export async function getAll(req: Request, res: Response) {
  const { createdBy } = req.query;
  try {
    if (!createdBy) {
      const scanners = await ScannerModel.find();
      return res.json(successResponse(scanners, "Scanners found"));
    }
    const scanners = await ScannerModel.find({ createdBy });
    return res.json(successResponse(scanners, "Scanners found"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

// Create a new scanner with a unique name and generate a Dockerfile
export async function create(req: Request, res: Response) {
  const { data } = req.body;
  try {
    // Check if a scanner with the same name already exists
    const scanner = await ScannerModel.findOne({ name: data.name });
    if (scanner) {
      return res.json(errorResponse("Scanner already exists"));
    }
    // Create a new scanner
    const newScanner = await ScannerModel.create({
      name: data.name,
      createdBy: req.user?.username ? req.user?.username : "admin",
      config: data.config,
    });
    // Generate Dockerfile based on the scanner config
    const dockerfile = await generateDockerfile(data.config);
    // Log the creation in the change history
    await ChangeHistoryModel.create({
      objectId: newScanner._id,
      action: "create",
      timestamp: Date.now(),
      description: `Account ${req.user?.username} create a new scanner`,
      account: req.user?._id ? req.user?._id : "67e2c58c055af0d862a5401c",
    });
    return res.json(successResponse(dockerfile, "Scanner created"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

// Get sample code for vulnerabilities
export async function getSampleCode(req: Request, res: Response) {
  return res.json(
    successResponse(
      {
        interface: vulnInterface,
        sampleCode: sampleCode,
      },
      "Sample code found"
    )
  );
}

// Get details of a specific scanner by ID
export async function get(req: Request, res: Response) {
  const { id } = req.params;
  try {
    const scanner = await ScannerModel.findById(id);
    return res.json(successResponse(scanner, "Scanner found"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

// Update a scanner configuration and regenerate the Dockerfile
export async function update(req: Request, res: Response) {
  const { data } = req.body;
  try {
    // Update scanner configuration in the database
    await ScannerModel.findOneAndUpdate(
      {
        name: data.name,
      },
      {
        config: {
          installCommand: data.config.installCommand,
          code: data.config.code,
        },
      }
    );
    // Generate a new Dockerfile based on the updated config
    const dockerfile = await generateDockerfile(data.config);
    return res.json(
      successResponse(
        dockerfile,
        "Scanner updated. New Dockerfile content is copied to your clipboard!"
      )
    );
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}


// Function to call the Dockerized document scanning service
export async function scanDocumentInDocker(artifact: Artifact) {
  try {
    const response = await axios.post('http://localhost:4000/docs', { artifact });
    return response.data.state;
  } catch (error) {
    console.error("[ERROR] Failed to scan document:", error);
    return "S1"; // Default state in case of error
  }
}

export async function scanSourceCode(artifact: Artifact, accountId: Types.ObjectId | undefined) {
  const artifactUrl: string = artifact.url ?? "";
  let check: boolean = true;
  console.log("[DEBUG] Account ID:", accountId);
  if (!accountId) {
    console.error("[ERROR] accountId is undefined!");
    return "S2"; // Tránh lỗi crash, có thể trả về trạng thái mặc định
  }
  if (artifactUrl.includes("github")) {
    console.log("[INFO] Scanning source github: ", artifact.name);
    check = await importGithubScanResult(accountId, artifactUrl);
  } else {
    console.log("[INFO] Scanning source gitlab: ", artifact.name);
    check = await importGitlabScanResult(accountId, artifactUrl);
  }
  console.log("[SUCCESS] Scanning source finish with state: ", check ? "S1" : "S2");
  return check ? "S1" : "S2";
}

