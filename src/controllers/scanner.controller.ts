import { Request, Response } from "express";
import { ArtifactModel, ChangeHistoryModel, ScannerModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import {
  generateDockerfile,
  sampleCode,
  vulnInterface,
} from "../utils/generateDockerfile";
import axios from 'axios';
import fs from 'fs';
import path from 'path';
import { fileTypeFromBuffer } from 'file-type';
import { exec } from 'child_process';
import { Artifact } from "../models/artifact";

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

// Define the interface for the function result
interface ScanResult {
  state: 'S1' | 'S2';
  sensitiveDataFound: boolean;
  isCompliant: boolean;
}

// Function to download the file from a URL
async function downloadFileFromUrl(url: string, outputPath: string): Promise<Buffer | null> {
  try {
    const response = await axios.get(url, { responseType: 'arraybuffer' });
    const buffer = Buffer.from(response.data);

    // Save the file to disk
    fs.writeFileSync(outputPath, buffer);
    return buffer;
  } catch (error) {
    console.error("Error downloading file:", error);
    return null;
  }
}

// Function to identify the file type
async function checkFileType(buffer: Buffer): Promise<string | null> {
  const type = await fileTypeFromBuffer(buffer);
  return type ? type.ext : null;
}

// Function to scan for sensitive data in a file
async function scanForSensitiveData(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    // Using TruffleHog or Gitleaks via command line to scan for sensitive data
    exec(`trufflehog --regex --entropy=False ${filePath}`, (error, stdout, stderr) => {
      if (error) {
        reject(`Error scanning file for sensitive data: ${stderr}`);
      } else {
        resolve(stdout);
      }
    });
  });
}

// Function to check if a document complies with security policies
async function checkPolicyCompliance(filePath: string): Promise<boolean> {
  // Implement compliance checks (e.g., check for certain keywords or rules)
  const compliancePolicyKeywords = ['confidential', 'internal use only', 'sensitive'];

  const fileContent = fs.readFileSync(filePath, 'utf8');
  const violations = compliancePolicyKeywords.filter(keyword => fileContent.includes(keyword));

  return violations.length === 0; // Return true if no violations, false if any violation
}

// Function to process the document, validate, and assign security status
export async function validateAndScanDocument(artifact: Artifact): Promise<ScanResult | string> {
  console.log(`[INFO] Starting document validation and scan for artifact: ${artifact._id}`);
  const url: string = artifact?.url ?? "";
  const outputPath = path.join(__dirname, 'downloads', path.basename(url));
  
  console.log(`[INFO] Downloading file from URL: ${url}`);
  const fileBuffer = await downloadFileFromUrl(url, outputPath);
  if (!fileBuffer) {
    console.error("[ERROR] Failed to download the file.");
    return '[ERROR] Failed to download the file.';
  }

  console.log("[SUCCESS] File downloaded successfully.");
  console.log("[INFO] Identifying file type...");
  const fileTypeExt = await checkFileType(fileBuffer);
  console.log(`[INFO] Detected file type: ${fileTypeExt}`);
  
  if (!fileTypeExt || !['pdf', 'docx', 'txt'].includes(fileTypeExt)) {
    console.error(`[ERROR] Invalid file type: ${fileTypeExt ?? 'unknown'}. Allowed types: .pdf, .docx, .txt`);
    return `[ERROR] Invalid file type: ${fileTypeExt ?? 'unknown'}. Only .pdf, .docx, or .txt are allowed.`;
  }

  console.log("[INFO] Scanning for sensitive data...");
  let sensitiveDataFound = false;
  try {
    const scanResult = await scanForSensitiveData(outputPath);
    console.log("[INFO] Scan result:", scanResult);
    
    if (scanResult.includes('No secrets found')) {
      sensitiveDataFound = false;
    } else {
      sensitiveDataFound = true;
    }
  } catch (error) {
    console.error("[ERROR] Error scanning file for sensitive data:", error);
    sensitiveDataFound = true;
  }

  console.log("[INFO] Checking document compliance with security policies...");
  const isCompliant = await checkPolicyCompliance(outputPath);
  console.log(`[INFO] Compliance check result: ${isCompliant ? 'Compliant' : 'Not compliant'}`);

  let state: 'S1' | 'S2' = 'S2';
  if (sensitiveDataFound || !isCompliant) {
    state = 'S1';
  }

  console.log(`[INFO] Assigning security state: ${state}`);
  
  try {
    await ArtifactModel.findByIdAndUpdate(artifact._id, { state });
    console.log(`[SUCCESS] Updated artifact ${artifact._id} to state: ${state}`);
  } catch (error) {
    console.error("[ERROR] Failed to update artifact state:", error);
    return "[ERROR] Failed to update artifact state.";
  }

  console.log("[INFO] Document validation and scanning process completed.");
  return {
    state,
    sensitiveDataFound,
    isCompliant,
  };
}

