import { Request, Response } from "express";
import { ArtifactModel, ThreatModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";

export async function getAll(req: Request, res: Response) {
  try {
    const threats = await ThreatModel.find();
    return res.json(successResponse(threats, "Threats retrieved successfully"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
export async function create(req: Request, res: Response) {
  const { data } = req.body;
  try {
    const threat = await ThreatModel.findOne({ name: data.name });
    if (threat) {
      return res.json(errorResponse(`Threat already exists`));
    }
    const newThreat = await ThreatModel.create(data);
    return res.json(
      successResponse(
        null,
        "Registered a new threat successfully. Threat is now available in the database"
      )
    );
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
// Sub-document of Artifact
export async function get(req: Request, res: Response) {
  const { id } = req.params;
  try {
    const artifact = await ArtifactModel.findOne({
      threatList: { $elemMatch: { _id: id } },
    });
    const threat = artifact?.threatList?.find((threat) => threat._id == id);
    if (!threat) {
      return res.json(errorResponse(`Threat not found`));
    }
    return res.json(successResponse(threat, "Threat retrieved successfully"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
// Sub-document of Artifact
export async function update(req: Request, res: Response) {
  const { data } = req.body;
  const { status, mitigation } = data;
  const { id } = req.params;
  try {
    await ArtifactModel.updateMany(
      { threatList: { $elemMatch: { _id: id } } },
      {
        $set: {
          "threatList.$.status": status,
          "threatList.$.mitigation": mitigation,
        },
      }
    );
    return res.json(successResponse(null, "Threat updated successfully"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
