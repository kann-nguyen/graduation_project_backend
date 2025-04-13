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
import { spawn } from "child_process";
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

// Create a new scanner with a unique name and generate a Dockerfile
export async function create(req: Request, res: Response) {
  const { data } = req.body;
  try {
    // Check if a scanner with the same name already exists
    const existingScanner = await ScannerModel.findOne({ name: data.name });
    if (existingScanner) {
      return res.json(errorResponse("Scanner already exists"));
    }
    
    // Create a new scanner document in the database
    const newScanner = await ScannerModel.create({
      name: data.name,
      createdBy: req.user?.username ?? "Tan Nguyen",
      config: data.config,
    });

    // Generate Dockerfile based on scanner config
    const dockerfileContent = await generateDockerfile(data.config);
    // Save Dockerfile to a temporary file
    const dockerfilePath = path.join(__dirname, "../temp", `${data.name}-Dockerfile`);
    await fs.writeFile(dockerfilePath, dockerfileContent, "utf-8");

    // Define unique names for the Docker image and container
    const imageName = `scanner-${newScanner._id.toString()}`;
    const containerName = `scanner-container-${newScanner._id.toString()}`;
    // Optionally decide the host port (it could be dynamic or predetermined)
    const hostPort = 3000; 
    const containerPort = 3000; // Adjust if your Dockerfile exposes a different port

    // Build the Docker image
    await buildDockerImage(dockerfilePath, imageName);

    // Run the Docker container and get its endpoint
    const endpoint = await runDockerContainer(imageName, containerName, hostPort, containerPort);
    
    // Update the scanner document with the endpoint
    newScanner.endpoint = endpoint;
    await newScanner.save();

    // Log the creation in the change history
    await ChangeHistoryModel.create({
      objectId: newScanner._id,
      action: "create",
      timestamp: Date.now(),
      description: `Account ${req.user?.username ?? "Tan Nguyen"} created a new scanner`,
      account: req.user?._id ?? "67f286bd35b165dc0adadacf",
    });
    
    // Optionally, you can return the endpoint and Dockerfile content as part of the response
    return res.json(successResponse({ dockerfile: dockerfileContent, endpoint }, "Scanner created and container is running"));
  } catch (error) {
    console.error("Error creating scanner:", error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export function buildDockerImage(dockerfilePath: string, imageName: string): Promise<void> {
  return new Promise((resolve, reject) => {
    // Run Docker build command
    const build = spawn("docker", ["build", "-t", imageName, "-f", dockerfilePath, "."]);

    build.stdout.on("data", (data) => {
      console.log(`Docker build stdout: ${data}`);
    });
    build.stderr.on("data", (data) => {
      console.error(`Docker build stderr: ${data}`);
    });
    build.on("close", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`Docker build failed with exit code ${code}`));
      }
    });
  });
}

export function runDockerContainer(imageName: string, containerName: string, hostPort: number, containerPort: number): Promise<string> {
  return new Promise((resolve, reject) => {
    // Run Docker run command in detached mode
    const run = spawn("docker", [
      "run",
      "-d", // detached mode
      "--name", containerName,
      "-p", `${hostPort}:${containerPort}`,
      imageName,
    ]);

    let containerId = "";
    run.stdout.on("data", (data) => {
      containerId += data.toString();
    });
    run.stderr.on("data", (data) => {
      console.error(`Docker run stderr: ${data}`);
    });
    run.on("close", (code) => {
      if (code === 0) {
        // Assuming the endpoint is on localhost, build endpoint URL string
        const endpointUrl = `http://localhost:${hostPort}`;
        resolve(endpointUrl);
      } else {
        reject(new Error(`Docker run failed with exit code ${code}`));
      }
    });
  });
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
  } catch (error) {
    console.error("[ERROR] Failed to scan document:", error);
  }
}

export async function scanSourceCode(artifact: Artifact) {
  try {
    await axios.post('http://localhost:5000/source', artifact.url);
  } catch (error) {
    console.error("[ERROR] Failed to scan document:", error);
  }
}

