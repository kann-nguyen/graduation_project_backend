import { Request, Response } from "express";
import {
  ArtifactModel,
  ChangeHistoryModel,
  PhaseModel,
  PhaseTemplateModel,
  ProjectModel,
  ThreatModel,
  TicketModel,
} from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import {
  fetchVulnsFromNVD,
  importGithubScanResult,
  importGitlabScanResult,
} from "../utils/vuln";
import axios from "axios";

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
        populate: {
          path: "threatList vulnerabilityList", // Populate danh sách threats và vulnerabilities
        },
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
  const username = req.user?.username;
  const { phases } = data;
  try {
    // Template check: To determine whether is a new template or an existing one
    if (!data._id) {
      const newTemplate = await PhaseTemplateModel.create({
        ...data,
        createdBy: username,
      });
      await ChangeHistoryModel.create({
        objectId: newTemplate._id,
        action: "create",
        timestamp: Date.now(),
        description: `Account ${req.user?.username} creates a new phase template id ${newTemplate._id}`,
        account: req.user?._id,
      });
    }
    // Create new phases
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
    const phasesCreated = await PhaseModel.insertMany(phasesWithoutIds);
    // Add phases to project
    await ProjectModel.findOneAndUpdate(
      { name: projectName },
      { phaseList: phasesCreated.map((phase) => phase._id) }
    );

    return res.json(successResponse(null, "Phases and template created"));
  } catch (error) {
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
  const { cpe, threatList, type, name, version, url: artifactUrl } = data;
  // Attempt to find CVEs if CPE exists
  if (cpe) {
    try {
      const vulns = await fetchVulnsFromNVD(cpe);
      data.vulnerabilityList = vulns;
    } catch (error) {
      data.vulnerabilityList = [];
    }
  }
  if (threatList) {
    // Attached threats to artifact
    try {
      const threats = await ThreatModel.find({ name: { $in: threatList } });
      data.threatList = threats;
    } catch (error) {
      data.threatList = [];
    }
  }
  try {
    const artifact = await ArtifactModel.create(data);
    const updatedPhase = await PhaseModel.findByIdAndUpdate(
      id,
      { $addToSet: { artifacts: artifact._id } },
      { new: true }
    );
    switch (type) {
      case "image":
        let url = `${process.env.IMAGE_SCANNING_URL}/image`;
        // Connect to scanner to init image scanning
        const account = req.user;
        if (account) {
          // Check for scanner preference
          const someEndpoint = account.scanner.endpoint;
          if (someEndpoint) {
            url = `${someEndpoint}/image`;
          }
        }
        try {
          axios.get(url, {
            params: {
              name: `${name}:${version}`,
            },
          });
          console.log(`Image scanning triggered for artifact: ${name}`);
        } catch (error) {
          break;
        }
        break;
      case "source code":
        if (artifactUrl.includes("github")) {
          await importGithubScanResult(req.user?._id, artifactUrl);
        } else {
          await importGitlabScanResult(req.user?._id, artifactUrl);
        }
        break;
      default:
        break;
    }
    return res.json(successResponse(null, "Artifact added to phase"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
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
