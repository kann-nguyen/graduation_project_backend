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
    console.log("[create] Checking if scanner with the same name exists...");

    const existingScanner = await ScannerModel.findOne({ name: data.name });
    if (existingScanner) {
      console.log("[create] Scanner already exists");
      return res.json(errorResponse("Scanner already exists"));
    }

    console.log("[create] Creating new scanner document in the database...");
    const newScanner = await ScannerModel.create({
      name: data.name,
      createdBy: req.user?.username ?? "Tan Nguyen",
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


// /**
//  * Builds a Docker image using the specified Dockerfile.
//  * @param dockerfilePath - The path to the Dockerfile.
//  * @param imageName - The tag/name for the Docker image.
//  * @returns A promise that resolves when the image build is successful.
//  */
// export function buildDockerImage(dockerfilePath: string, imageName: string): Promise<void> {
//   console.log(`[buildDockerImage] Starting Docker build for image: ${imageName} using Dockerfile at: ${dockerfilePath}`);
//   return new Promise((resolve, reject) => {
//     // Spawn a child process to run the Docker build command.
//     const build = spawn("docker", ["build", "-t", imageName, "-f", dockerfilePath, "."]);

//     build.stdout.on("data", (data) => {
//       console.log(`[buildDockerImage] stdout: ${data}`);
//     });

//     build.stderr.on("data", (data) => {
//       console.error(`[buildDockerImage] stderr: ${data}`);
//     });

//     build.on("close", (code) => {
//       if (code === 0) {
//         console.log(`[buildDockerImage] Docker image ${imageName} built successfully.`);
//         resolve();
//       } else {
//         console.error(`[buildDockerImage] Docker build failed with exit code ${code}`);
//         reject(new Error(`Docker build failed with exit code ${code}`));
//       }
//     });
//   });
// }

// /**
//  * Runs a Docker container from the specified image and returns the endpoint URL.
//  * @param imageName - The name of the Docker image to run.
//  * @param containerName - The name for the running Docker container.
//  * @param hostPort - The port on the host machine.
//  * @param containerPort - The port exposed by the container.
//  * @returns A promise that resolves to the endpoint URL string.
//  */
// export function runDockerContainer(imageName: string, containerName: string, hostPort: number, containerPort: number): Promise<string> {
//   console.log(`[runDockerContainer] Starting Docker container '${containerName}' from image '${imageName}'.`);
//   return new Promise((resolve, reject) => {
//     // Spawn a child process to run the Docker run command in detached mode.
//     const run = spawn("docker", [
//       "run",
//       "-d", // Run container in detached mode.
//       "--name", containerName,
//       "-p", `${hostPort}:${containerPort}`,
//       imageName,
//     ]);

//     let containerId = "";
//     run.stdout.on("data", (data) => {
//       containerId += data.toString();
//       console.log(`[runDockerContainer] stdout: ${data}`);
//     });

//     run.stderr.on("data", (data) => {
//       console.error(`[runDockerContainer] stderr: ${data}`);
//     });

//     run.on("close", (code) => {
//       if (code === 0) {
//         // Trim the container ID received and build the endpoint URL.
//         containerId = containerId.trim();
//         console.log(`[runDockerContainer] Docker container '${containerName}' started successfully with ID: ${containerId}`);
//         const endpointUrl = `http://localhost:${hostPort}`;
//         resolve(endpointUrl);
//       } else {
//         console.error(`[runDockerContainer] Docker run failed with exit code ${code}`);
//         reject(new Error(`Docker run failed with exit code ${code}`));
//       }
//     });
//   });
// }


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

