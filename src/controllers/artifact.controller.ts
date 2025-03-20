import { isDocumentArray } from "@typegoose/typegoose";
import { Request, Response } from "express";
import { ArtifactModel, ProjectModel, ThreatModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";

export async function getAll(req: Request, res: Response) {
  const { projectName } = req.query;
  try {
    const project = await ProjectModel.findOne({
      name: projectName,
    }).populate({
      path: "phaseList",
      populate: {
        path: "artifacts",
      },
    });
    if (!project) {
      return res.json(errorResponse("Project not found"));
    }
    if (isDocumentArray(project.phaseList)) {
      const artifacts = project.phaseList
        .map((phase) => phase.artifacts)
        .flat();
      return res.json(
        successResponse(
          artifacts,
          "Get all artifacts with respective vulnerabilities"
        )
      );
    }
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
export async function get(req: Request, res: Response) {
  const { id } = req.params;
  try {
    const artifact = await ArtifactModel.findById(id);
    return res.json(successResponse(artifact, "Artifact fetched successfully"));
  } catch (error) {
    return res.json(error);
  }
}
export async function update(req: Request, res: Response) {
  const { id } = req.params;
  const { data } = req.body;
  const { threatList } = data; // Array of threat's name
  try {
    const threats = await ThreatModel.find({ name: { $in: threatList } });
    const artifact = await ArtifactModel.findByIdAndUpdate(
      id,
      {
        ...data,
        threatList: threats, // Using sub-document binding
      },
      {
        new: true,
      }
    );
    return res.json(successResponse(artifact, "Artifact updated successfully"));
  } catch (error) {
    return res.json(error);
  }
}
