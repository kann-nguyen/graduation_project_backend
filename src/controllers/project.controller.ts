import { Request, Response } from "express";
import { PhaseModel, ProjectModel, UserModel } from "../models/models";
import { Phase } from "../models/phase";
import { errorResponse, successResponse } from "../utils/responseFormat";
export async function get(req: Request, res: Response) {
  try {
    const { projectName } = req.params;
    const project = await ProjectModel.findOne({ name: projectName }).populate({
      path: "phaseList",
      options: {
        sort: {
          order: 1,
        },
      },
      populate: [
        {
          path: "tasks",
        },
        {
          path: "artifacts",
          populate: {
            path: "threatList vulnerabilityList",
          },
        },
      ],
    });
    return res.json(successResponse(project, "Project found"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function create(req: Request, res: Response) {
  const { data } = req.body;
  const { type, data: createData } = data;
  try {
    if (type === "import") {
      const { name, url } = createData;
      const project = await ProjectModel.create({
        name,
        url,
        createdBy: req.user?.username,
      });
      // Add project to user
      await UserModel.findOneAndUpdate(
        {
          account: req.user?._id,
        },
        {
          $addToSet: {
            projectIn: project._id,
          },
        }
      );
      return res.json(successResponse(project, "Project created"));
    }
    if (type === "create") {
      // TODO
    }
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function updateStatus(req: Request, res: Response) {
  try {
    const { projectName } = req.params;
    const { status } = req.body;
    const project = await ProjectModel.findOneAndUpdate(
      { name: projectName },
      { status },

      { new: true }
    );
    return res.json(successResponse(null, "Project status updated"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function remove(req: Request, res: Response) {
  const { projectName } = req.params;
  const { id } = req.params;
  try {
    const project = await ProjectModel.findOne({ name: projectName });
    if (!project) {
      return res.json(errorResponse("Project not found"));
    }
    await ProjectModel.findByIdAndDelete(id);
    return res.json(successResponse(null, "Project deleted"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function getProjectMembers(req: Request, res: Response) {
  try {
    const { projectName } = req.params;
    const project = await ProjectModel.findOne({ name: projectName });
    if (!project) {
      return res.json(errorResponse("Project not found"));
    }
    const users = await UserModel.find({ projectIn: project._id })
      .populate({
        path: "activityHistory",
        match: { projectId: project._id },
      })
      .populate({
        path: "taskAssigned",
        match: { projectName },
      })
      .populate({
        path: "account",
      });
    return res.json(successResponse(users, "Users found"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function addMemberToProject(req: Request, res: Response) {
  const { projectName } = req.params;
  const {
    data: { accountId },
  } = req.body;
  try {
    const project = await ProjectModel.findOne({ name: projectName });
    if (!project) {
      return res.json(errorResponse("Project not found"));
    }
    await UserModel.findOneAndUpdate(
      {
        account: accountId,
      },
      {
        $addToSet: {
          projectIn: project._id,
        },
      }
    );
    return res.json(successResponse(project, "Member added to project"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function removeMemberFromProject(req: Request, res: Response) {
  const { projectName } = req.params;
  const { accountId } = req.body;
  try {
    const project = await ProjectModel.findOne({ name: projectName });
    if (!project) {
      return res.json(errorResponse("Project not found"));
    }
    await UserModel.findOneAndUpdate(
      {
        account: accountId,
      },
      {
        $pull: {
          projectIn: project._id,
        },
      }
    );
    return res.json(successResponse(project, "Member added to project"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
