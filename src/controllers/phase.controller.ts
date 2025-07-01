import { Request, Response } from "express";
import {
  ArtifactModel,
  ChangeHistoryModel,
  PhaseModel,
  PhaseTemplateModel,
  ProjectModel,
  ScannerModel,
  ThreatModel,
  TicketModel,
  UserModel,
} from "../models/models";
import { errorResponse, successResponse, handleScanningError } from "../utils/responseFormat";
import {
  fetchVulnsFromNVD,
} from "../utils/vuln";
import { Artifact } from "../models/artifact";
import {
  scanDocumentInDocker,
  scanSourceCode
} from "./scanner.controller"
import axios from "axios";
import { validateArtifact } from "../utils/validateArtifact";
import scanner from "../routes/scanner";
import { ArtifactWorkflowController } from "./artifactWorkflow.controller";

// Lấy thông tin chi tiết của một Phase theo ID
export async function get(req: Request, res: Response) {
  const { id } = req.params; // Lấy ID của Phase từ request params
  try {
    // Tìm Phase theo ID và populate dữ liệu liên quan
    const phase = await PhaseModel.findById(id).populate([
      {
        path: "tasks", // Lấy danh sách tasks liên quan đến Phase
      },
      {
        path: "artifacts", // Lấy danh sách artifacts của Phase
        select: "name type url version threatList vulnerabilityList cpe isScanning state", // Explicitly include state field
        populate: {
          path: "threatList vulnerabilityList", // Populate danh sách threats và vulnerabilities
        },
      },
      {
        path: "scanners", // Lấy danh sách scanners của Phase
      },
    ]);

    // Trả về thông tin Phase nếu tìm thấy
    return res.json(successResponse(phase, "Phase found"));
  } catch (error) {
    // Xử lý lỗi nếu có vấn đề trong quá trình truy vấn
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function createFromTemplate(req: Request, res: Response) {
  const { data, projectName } = req.body;
  //const username = req.user?.username;
  const username = "Github_kann-nguyen";
  const { phases } = data;

  console.log(`[INFO] Received request to create from template for project: ${projectName}`);
  console.log(`[INFO] Request initiated by user: ${username}`);

  try {
    let newTemplateId = null;

    // Kiểm tra template có tồn tại hay không
    if (!data._id) {
      console.log(`[INFO] Creating a new phase template with name: ${data.name}`);

      const newTemplate = await PhaseTemplateModel.create({
        ...data,
        createdBy: username,
      });

      newTemplateId = newTemplate._id;

      console.log(`[SUCCESS] Created new template ID: ${newTemplateId}`);

      await ChangeHistoryModel.create({
        objectId: newTemplateId,
        action: "create",
        timestamp: Date.now(),
        description: `Account ${req.user?.username} creates a new phase template id ${newTemplateId}`,
        account: "67f286bd35b165dc0adadac7", //req.user?._id,
      });

      console.log(`[INFO] Logged change history for template ID: ${newTemplateId}`);
    } else {
      console.log(`[INFO] Using existing template ID: ${data._id}`);
    }

    // Tạo danh sách phases mới
    const phasesWithoutIds = phases.map(
      ({
        name,
        description,
        order,
      }: {
        name: string;
        description: string;
        order: number;
      }) => ({
        name,
        description,
        order,
      })
    );

    console.log(`[INFO] Creating ${phasesWithoutIds.length} phases for project: ${projectName}`);

    const phasesCreated = await PhaseModel.insertMany(phasesWithoutIds);

    console.log(`[SUCCESS] Created phases with IDs: ${phasesCreated.map((p) => p._id).join(", ")}`);

    // Cập nhật danh sách phase vào project
    await ProjectModel.findOneAndUpdate(
      { name: projectName },
      { phaseList: phasesCreated.map((phase) => phase._id) }
    );

    console.log(`[SUCCESS] Updated project ${projectName} with new phases`);

    return res.json(successResponse(null, "Phases and template created"));
  } catch (error) {
    console.error(`[ERROR] Internal server error: ${error}`);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}


export async function update(req: Request, res: Response) {
  const { id } = req.params;
  const { data } = req.body;
  try {
    const updatedPhase = await PhaseModel.findByIdAndUpdate(id, data, {
      new: true,
    });
    return res.json(successResponse(null, "Phase updated"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function remove(req: Request, res: Response) {
  const { id } = req.params;
  try {
    const deletedPhase = await PhaseModel.findByIdAndDelete(id);
    return res.json(successResponse(null, "Phase deleted"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function addTaskToPhase(req: Request, res: Response) {
  const { id, taskId } = req.params;
  try {
    const updatedPhase = await PhaseModel.findByIdAndUpdate(
      id,
      { $addToSet: { tasks: taskId } },

      { new: true }
    );
    return res.json(successResponse(null, "Task added to phase"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function removeTaskFromPhase(req: Request, res: Response) {
  const { id, taskId } = req.params;
  try {
    const updatedPhase = await PhaseModel.findByIdAndUpdate(
      id,
      { $pull: { tasks: taskId } },

      { new: true }
    );
    return res.json(successResponse(null, "Task removed from phase"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function getTemplates(req: Request, res: Response) {
  const username = req.user?.username;
  try {
    const templates = await PhaseTemplateModel.find().or([
      { isPrivate: false },
      { createdBy: username },
    ]);
    return res.json(successResponse(templates, "Phase templates found"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function addArtifactToPhase(req: Request, res: Response) {
  const { id } = req.params;
  const { data } = req.body;
  const { cpe, threatList } = data;
  
  // Get account ID from authenticated user
  const accountId = req.user?._id;
  console.log("AccountId: " + accountId);

  try {
    // Find user with this account ID
    if (!accountId) {
      return res.json(errorResponse("User not authenticated"));
    }

    const user = await UserModel.findOne({ account: accountId });
    if (!user) {
      return res.json(errorResponse("User not found"));
    }
    
    // Find the project that contains this phase (correct approach)
    const project = await ProjectModel.findOne({ phaseList: id });
    if (!project) {
      console.log("No project found containing phase ID:", id);
      return res.json(errorResponse("Project containing this phase not found"));
    }
    
    // Verify that the user is a member of this project
    if (!user.projectIn.includes(project._id)) {
      console.log("User is not a member of the project containing this phase");
      return res.json(errorResponse("User is not authorized to add artifacts to this phase"));
    }
    
    // Set the correct project ID based on the phase's parent project
    data.projectId = project._id.toString();
    console.log("Setting projectId to:", data.projectId, "for project:", project.name);
    
    // Validate artifact before proceeding
    const validationResult = await validateArtifact(data);
    
    // Set the state based on validation result
    data.state = validationResult.valid ? "valid" : "invalid";
  

    // Fetch vulnerabilities and threats before creating artifact
    if (cpe) { 
      try {
        const vulns = await fetchVulnsFromNVD(cpe);
        data.vulnerabilityList = vulns;
      } catch (error) {
        data.vulnerabilityList = [];
        console.error("[ERROR] Failed to fetch vulnerabilities", error);
      }
    }

    if (threatList) {
      try {
        const threats = await ThreatModel.find({ name: { $in: threatList } });
        data.threatList = threats;
      } catch (error) {
        data.threatList = [];
      }
    }    try {
      // Get the phase to determine scanner count before creating artifact
      const phase = await PhaseModel.findById(id);
      const scannerCount = phase?.scanners?.length || 0;
      
      console.log(`[DEBUG] Phase ${id} has ${scannerCount} scanners`);
      
      // Initialize scanning-related fields
      data.totalScanners = Math.max(scannerCount, 1);
      data.scannersCompleted = 0;
      data.isScanning = false; // Will be set to true when scanning starts
      
      console.log(`[DEBUG] Setting totalScanners to: ${data.totalScanners}, scannersCompleted to: ${data.scannersCompleted}`);      const artifact = await ArtifactModel.create(data);
      
      console.log(`[DEBUG] Created artifact ${artifact._id} with totalScanners: ${artifact.totalScanners}, scannersCompleted: ${artifact.scannersCompleted}`);

      // ✅ Thêm artifact vào phase ngay lập tức
      await PhaseModel.findByIdAndUpdate(
        id,
        { $addToSet: { artifacts: artifact._id } },
        { new: true }
      );
      
      // ✅ Initialize workflow cycle for the artifact
      try {
        await ArtifactWorkflowController.updateWorkflowStatus(artifact._id, 1);
      } catch (workflowError) {
        console.error(`[ERROR] Failed to initialize workflow:`, workflowError);
      }
  

      // ✅ Bắt đầu scan ở background only if artifact is valid
      if (artifact.state === "valid") {
        res.json(successResponse(null, "Artifact added to phase and scanning started in background"));
        setImmediate(async () => {
          try {
            await scanArtifact(artifact, id);
          } catch (error) {
            console.error("[ERROR] Scanning failed:", error);
          }
        });
      } else {
        res.json(successResponse(null, `Artifact added to phase but is not valid${validationResult.error}`));
      }

    } catch (error) {
      console.error("[ERROR] Internal server error", error);
      return res.json(errorResponse(`Internal server error: ${error}`));
    }
  } catch (error) {
    console.error("[ERROR] User lookup failed", error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}


export async function scanArtifact(artifact: Artifact, phaseId: string) {
  console.log("[INFO] Scanning artifact", artifact.name);

  // First, get the phase to retrieve all scanner IDs
  const phase = await PhaseModel.findById(phaseId);
  if (!phase) {
    console.error("[ERROR] Phase not found for artifact", artifact.name);
    return;
  }
  
  // Get scanner IDs from the phase
  const scannerIds = phase.scanners || [];

  const artifactImage = await ArtifactModel.findById(artifact._id);
  if (!artifactImage) {
    console.error("[ERROR] Artifact not found in the database");
    return;
  }

  // Skip scanning if the artifact is invalid
  if (artifactImage.state === "invalid") {
    console.log(`[INFO] Skipping scanning for invalid artifact: ${artifact.name}`);
    return;
  }

  artifactImage.totalScanners = Math.max(scannerIds.length, 1);
  console.log(`[DEBUG] Setting totalScanners to ${artifactImage.totalScanners} for artifact ${artifact.name}`);
  artifactImage.scannersCompleted = 0;
  artifactImage.isScanning = true; // Set scanning flag to true
  await artifactImage.save();

  try {
    // Fall back to default scanner behavior if no custom scanners were successful
    switch (artifact.type) {
      case "docs":
        await scanDocumentInDocker(artifact);
        break;
      case "source code":
        await scanSourceCode(artifact);
        break;      case "image":
        // If we have scanners in the phase, try to use them first
        if (scannerIds.length > 0) {
          console.log(`[INFO] Found ${scannerIds.length} scanner IDs for phase. Will attempt to use them for image scanning.`);
          console.log(`[DEBUG] Scanner IDs: ${scannerIds.join(', ')}`);
          
          // Process all scanners in parallel using Promise.allSettled
          const scannerPromises = scannerIds.map(async (scannerId, index) => {
            console.log(`[DEBUG] Processing scanner ${index + 1}/${scannerIds.length} with ID: ${scannerId}`);
            
            // Get the full scanner document by ID
            const scanner = await ScannerModel.findById(scannerId);
            
            if (!scanner) {
              console.log(`[WARNING] Scanner with ID ${scannerId} not found in database`);
              return { status: 'error', reason: 'Scanner not found' };
            }
            
            console.log(`[DEBUG] Found scanner: ${scanner.name} with endpoint: ${scanner.endpoint}`);
            
            // Now we have the full scanner document with all properties
            if (scanner.endpoint) {
              try {
                console.log(`[INFO] Calling scanner ${scanner.name} at endpoint ${scanner.endpoint}`);
                // Determine if we need HTTPS agent based on endpoint URL
                const isHttps = scanner.endpoint.startsWith('https://');
                let requestConfig: any = {
                  timeout: 600000, // 10 minute timeout (increased from 5 minutes)
                };
                
                if (isHttps) {
                  // Create HTTPS agent only for HTTPS endpoints
                  const https = require('https');
                  requestConfig.httpsAgent = new https.Agent({
                    rejectUnauthorized: false // Ignore SSL certificate verification for development
                  });
                }
                
                // Make the API call to the scanner - use GET with params for compatibility
                const response = await axios.get(`${scanner.endpoint}`, {
                  params: {
                    name: `${artifact.name}:${artifact.version}`,
                  },
                  ...requestConfig
                });
                
                console.log(`[SUCCESS] Scanner ${scanner.name} responded with status: ${response.status}`);
                return { status: 'success', value: response };
              } catch (error) {
                if (error instanceof Error) {
                  // Handle timeout specifically
                  if (error.message.includes('timeout') || (error as any).code === 'ECONNABORTED') {
                    console.error(`[TIMEOUT] Scanner ${scanner.name} timed out after 10 minutes. This is expected for large scans.`);
                    console.log(`[INFO] Scan is still running in background for ${scanner.name}. Results will be sent via webhook when complete.`);
                  } else {
                    console.error(`[ERROR] Failed to call scanner ${scanner.name}:`, error.message);
                  }
                } else {
                  console.error(`[ERROR] Failed to call scanner ${scanner.name}:`, error);
                }
                // Don't re-throw the error - let the scanning continue in background
                return { status: 'rejected', reason: error };
              }
            } else {
              console.log(`[WARNING] Scanner ${scanner.name} has no endpoint defined`);
              return { status: 'rejected', reason: 'No endpoint defined' };
            }
          });

          // Wait for all scanner calls to complete (either fulfill or reject)
          const results = await Promise.allSettled(scannerPromises);
          
          // Log the results
          results.forEach((result, index) => {
            const scannerId = scannerIds[index];
            if (result.status === 'fulfilled') {
              console.log(`[DEBUG] Scanner ${index + 1} (ID: ${scannerId}) completed successfully`);
            } else {
              console.log(`[DEBUG] Scanner ${index + 1} (ID: ${scannerId}) failed or was rejected: ${result.reason}`);
            }
          });

          console.log(`[INFO] Completed processing all ${scannerIds.length} scanners for image scanning`);
        } else {
          let url = `${process.env.IMAGE_SCANNING_URL}/scan`;
          // Create a custom HTTPS agent that ignores SSL certificate errors
          // This is useful for development/testing with ngrok
          const https = require('https');
          const httpsAgent = new https.Agent({
            rejectUnauthorized: false // Ignore SSL certificate verification
          });
          
          try {
            const response = await axios.get(url, {
              params: {
                name: `${artifact.name}:${artifact.version}`,
              },
              timeout: 600000, // 10 minute timeout (increased from default)
              httpsAgent // Use the custom agent to bypass SSL verification
            });
            console.log(`[SUCCESS] Image scanning triggered for artifact: ${artifact.name}, status: ${response.status}`);
          } catch (error) {
            if (error instanceof Error) {
              // Handle timeout specifically
              if (error.message.includes('timeout') || (error as any).code === 'ECONNABORTED') {
                console.error(`[TIMEOUT] Default scanner timed out after 10 minutes for artifact: ${artifact.name}. This is expected for large scans.`);
                console.log(`[INFO] Scan is still running in background. Results will be sent via webhook when complete.`);
              } else {
                console.error(`[ERROR] Failed to call default scanner:`, error.message);
              }
            } else {
              console.error(`[ERROR] Failed to call default scanner:`, error);
            }
            // Don't re-throw the error - let the scanning continue in background
          }
        }
        break;
      default:
        console.log("[INFO] Unknown artifact type, assigning default state");
        break;
    }
  } catch (error) {
    // In case of error, reset scanning state
    artifactImage.isScanning = false;
    await artifactImage.save();
    
    // Handle different types of errors appropriately
    if (error instanceof Error) {
      if (error.message.includes('timeout') || (error as any).code === 'ECONNABORTED') {
        console.error(`[TIMEOUT] Scanning operation timed out for artifact: ${artifact.name}. Scan may still be running in background.`);
      } else {
        console.error(`[ERROR] Scanning failed for artifact: ${artifact.name}:`, error.message);
      }
    } else {
      console.error(`[ERROR] Scanning failed for artifact: ${artifact.name}:`, error);
    }
    // Don't re-throw the error to prevent app crash
  } finally {
    // Only set scanning flag to false for synchronous operations (docs, source code)
    // For async operations (image scanning), the flag will be reset when all scanner results are received
    if (artifact.type === "docs" || artifact.type === "source code") {
      artifactImage.isScanning = false;
      await artifactImage.save();
      console.log(`[INFO] Scanning completed for artifact: ${artifact.name}`);
    } else {
      console.log(`[INFO] Async scanning initiated for artifact: ${artifact.name}. Status will be updated when all scanners complete.`);
    }
  }
}

export async function removeArtifactFromPhase(req: Request, res: Response) {
  const { id, artifactId } = req.params;
  try {
    await PhaseModel.findByIdAndUpdate(id, {
      $pull: { artifacts: artifactId },
    });
    await ArtifactModel.findByIdAndDelete(artifactId);
    // Delete all tickets associated with this artifact
    await TicketModel.deleteMany({ artifactId: artifactId });
    return res.json(successResponse(null, "Artifact removed from phase"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function getOneTemplate(req: Request, res: Response) {
  const { id } = req.params;
  try {
    const template = await PhaseTemplateModel.findById(id);
    return res.json(successResponse(template, "Phase template found"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function updateTemplate(req: Request, res: Response) {
  const { id } = req.params;
  const { data } = req.body;
  try {
    await PhaseTemplateModel.findByIdAndUpdate(id, data);
    await ChangeHistoryModel.create({
      objectId: id,
      action: "update",
      timestamp: Date.now(),
      description: `Account ${req.user?.username} updates phase template id ${id}`,
      account: req.user?._id,
    });
    return res.json(successResponse(null, "Phase template updated"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function deleteTemplate(req: Request, res: Response) {
  const { id } = req.params;
  try {
    await PhaseTemplateModel.findByIdAndDelete(id);
    await ChangeHistoryModel.create({
      objectId: id,
      action: "delete",
      timestamp: Date.now(),
      description: `Account ${req.user?.username} deletes phase template id ${id}`,
      account: req.user?._id,
    });
    return res.json(successResponse(null, "Phase template deleted"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function createPhaseTemplate(req: Request, res: Response) {
  const { data } = req.body;
  try {
    const newTemplate = await PhaseTemplateModel.create({
      ...data,
      createdBy: req.user?.username,
    });
    await ChangeHistoryModel.create({
      objectId: newTemplate._id,
      action: "create",
      timestamp: Date.now(),
      description: `Account ${req.user?.username} creates a new phase template id ${newTemplate._id}`,
      account: req.user?._id,
    });
    return res.json(successResponse(null, "Phase template created"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function addScannerToPhase(req: Request, res: Response) {
  const { phaseId, scannerId } = req.body;

  try {
    // Check if the phase exists
    const phase = await PhaseModel.findById(phaseId);
    if (!phase) {
      return res.json(errorResponse("Phase not found"));
    }

    // Check if the scanner exists
    const scanner = await ScannerModel.findById(scannerId);
    if (!scanner) {
      return res.json(errorResponse("Scanner not found"));
    }

    // Check if scanner already exists in the phase
    if (phase.scanners?.includes(scanner._id)) {
      return res.json(errorResponse("Scanner already added to this phase"));
    }

    // Add scanner to phase
    phase.scanners?.push(scanner._id);
    await phase.save();

    return res.json(successResponse(phase, "Scanner added to phase successfully"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function removeScannerFromPhase(req: Request, res: Response) {
  const { phaseId, scannerId } = req.body;

  try {
    // Check if the phase exists
    const phase = await PhaseModel.findById(phaseId);
    if (!phase) {
      return res.json(errorResponse("Phase not found"));
    }

    // Check if the scanner exists
    const scanner = await ScannerModel.findById(scannerId);
    if (!scanner) {
      return res.json(errorResponse("Scanner not found"));
    }

    // Check if scanner exists in the phase
    if (!phase.scanners?.includes(scanner._id)) {
      return res.json(errorResponse("Scanner not found in this phase"));
    }

    // Remove scanner from phase
    await PhaseModel.findByIdAndUpdate(phaseId, {
      $pull: { scanners: scannerId },
    });

    return res.json(successResponse(null, "Scanner removed from phase successfully"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
