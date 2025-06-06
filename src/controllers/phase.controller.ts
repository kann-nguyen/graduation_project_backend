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
import { errorResponse, successResponse } from "../utils/responseFormat";
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

  let user = null;
  try {
    // Find user with this account ID
    if (accountId) {
      user = await UserModel.findOne({ account: accountId });
      console.log("Looking for user with account ID:", accountId);
    }
    
    if (!user) {
      return res.json(errorResponse("User not found"));
    }
    
    data.projectId = user.projectIn[0]?.toString() || "";
      // Check if projectId exists
    if (!data.projectId) {
      console.log("No project associated with user");
      return res.json(errorResponse("No project associated with user"));
    }
    
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
      const artifact = await ArtifactModel.create(data);

      // ✅ Thêm artifact vào phase ngay lập tức
      await PhaseModel.findByIdAndUpdate(
        id,
        { $addToSet: { artifacts: artifact._id } },
        { new: true }
      );      // ✅ Trả về response ngay, để user thấy artifact trong phase
  

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
  console.log(`[INFO] Found ${scannerIds.length} scanner references in phase`);

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
        break;
      case "image":        // If we have scanners in the phase, try to use them first
        if (scannerIds.length > 0) {
          console.log(`[INFO] Found ${scannerIds.length} scanner IDs for phase. Will attempt to use them for image scanning.`);
          
          // Fetch and use each scanner by ID
          for (const scannerId of scannerIds) {
            // Get the full scanner document by ID
            const scanner = await ScannerModel.findById(scannerId);
            
            if (!scanner) {
              console.log(`[WARNING] Scanner with ID ${scannerId} not found in database`);
              continue;
            }
            
            // Now we have the full scanner document with all properties
            if (scanner.endpoint) {
              try {
                console.log(`[INFO] Calling scanner ${scanner.name} at endpoint ${scanner.endpoint}`);
                
                // Determine if we need HTTPS agent based on endpoint URL
                const isHttps = scanner.endpoint.startsWith('https://');
                let requestConfig: any = {
                  timeout: 300000, // 30 second timeout
                };
                
                if (isHttps) {
                  // Create HTTPS agent only for HTTPS endpoints
                  const https = require('https');
                  requestConfig.httpsAgent = new https.Agent({
                    rejectUnauthorized: false // Ignore SSL certificate verification for development
                  });
                }
                
                // Make the API call to the scanner - use GET with params for compatibility
                axios.get(`${scanner.endpoint}`, {
                  params: {
                    name: `${artifact.name}:${artifact.version}`,
                  },
                  ...requestConfig
                });
              } catch (error) {
                if (error instanceof Error) {
                  console.error(`[ERROR] Failed to call scanner ${scanner.name}:`, error.message);
                } else {
                  console.error(`[ERROR] Failed to call scanner ${scanner.name}:`, error);
                }
              }
            } else {
              console.log(`[WARNING] Scanner ${scanner.name} has no endpoint defined`);
            }
          }
        } else {
          let url = `${process.env.IMAGE_SCANNING_URL}/scan`;
        
          // Create a custom HTTPS agent that ignores SSL certificate errors
          // This is useful for development/testing with ngrok
          const https = require('https');
          const httpsAgent = new https.Agent({
            rejectUnauthorized: false // Ignore SSL certificate verification
          });
          
          await axios.get(url, {
            params: {
              name: `${artifact.name}:${artifact.version}`,
            },
            httpsAgent // Use the custom agent to bypass SSL verification
          });
          console.log(`Image scanning triggered for artifact: ${artifact.name}`);
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
    console.error("[ERROR] Scanning failed:", error);
  } finally {
    // Set scanning flag to false when all scanning is done
    artifactImage.isScanning = false;
    await artifactImage.save();
    console.log(`[INFO] Scanning completed for artifact: ${artifact.name}`);
  }
}

export async function removeArtifactFromPhase(req: Request, res: Response) {
  const { id, artifactId } = req.params;
  try {
    await PhaseModel.findByIdAndUpdate(id, {
      $pull: { artifacts: artifactId },
    });
    await ArtifactModel.findByIdAndDelete(artifactId);
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
