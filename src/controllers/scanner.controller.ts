import { Request, Response } from "express";
import { ArtifactModel, ChangeHistoryModel, ScannerModel } from "../models/models";
import { errorResponse, successResponse, handleScanningError } from "../utils/responseFormat";
import {
  generateDockerfile,
  sampleCode,
  vulnInterface,
} from "../utils/generateDockerfile";
import axios from 'axios';
import { Artifact } from "../models/artifact";
import path from "path";
import * as fs from "fs/promises";


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

/**
 * Create a scanner document, generate and save a Dockerfile, return file path.
 */
export async function create(req: Request, res: Response) {
  const { data } = req.body;

  try {
    const existingScanner = await ScannerModel.findOne({ name: data.name });
    if (existingScanner) {
      return res.json(errorResponse("Scanner already exists"));
    }

    const newScanner = await ScannerModel.create({
      name: data.name,
      createdBy: req.user?.username ?? "Tan Nguyen",
      endpoint: data.endpoint, // Save the endpoint URL
      config: data.config,
    });

    console.log("[create] Generating Dockerfile from scanner config...");
    const dockerfileContent = await generateDockerfile(data.config);

    const tempDir = path.join("scanner-file");
    await fs.mkdir(tempDir, { recursive: true }); // Ensure temp dir exists

    const dockerfilePath = path.join(tempDir, `${newScanner.name.replace(/\s+/g, "-")}-Dockerfile`);
    console.log(`[create] Saving Dockerfile to: ${dockerfilePath}`);
    await fs.writeFile(dockerfilePath, dockerfileContent, "utf-8");

    console.log("[create] Logging creation in change history...");
    await ChangeHistoryModel.create({
      objectId: newScanner._id,
      action: "create",
      timestamp: Date.now(),
      description: `Account ${req.user?.username ?? "Tan Nguyen"} created a new scanner`,
      account: req.user?._id ?? "67f286bd35b165dc0adadacf",
    });

    console.log("[create] Returning Dockerfile path...");
    return res.json(
      successResponse(
        dockerfileContent,
        "Scanner created."
      )
    );
  } catch (error) {
    console.error("Error creating scanner:", error);
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
        endpoint: data.endpoint,
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
    const response = await axios.post('http://localhost:4000/docs', { 
      artifact,
    }, {
      timeout: 600000, // 10 minute timeout
    });
    console.log(`[SUCCESS] Document scanning completed for ${artifact.name}, status: ${response.status}`);
  } catch (error) {
    const errorInfo = handleScanningError(error, `Document scanning for ${artifact.name}`);
    
    if (errorInfo.isTimeout) {
      console.error(`[TIMEOUT] ${errorInfo.message}`);
      console.log(`[INFO] Document scan may still be running in background. Results will be sent via webhook when complete.`);
    } else {
      console.error(`[ERROR] ${errorInfo.message}`);
    }
    // Don't re-throw the error to prevent app crash
  }
}

export async function scanSourceCode(artifact: Artifact) {
  try {
    const response = await axios.post('http://localhost:5000/source', artifact.url, {
      timeout: 600000, // 10 minute timeout
    });
    console.log(`[SUCCESS] Source code scanning completed for ${artifact.name}, status: ${response.status}`);
  } catch (error) {
    const errorInfo = handleScanningError(error, `Source code scanning for ${artifact.name}`);
    
    if (errorInfo.isTimeout) {
      console.error(`[TIMEOUT] ${errorInfo.message}`);
      console.log(`[INFO] Source code scan may still be running in background. Results will be sent via webhook when complete.`);
    } else {
      console.error(`[ERROR] ${errorInfo.message}`);
    }
    // Don't re-throw the error to prevent app crash
  }
}

