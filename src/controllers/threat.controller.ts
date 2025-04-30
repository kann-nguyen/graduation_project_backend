import { Request, Response } from "express";
import mongoose from "mongoose";
import { ArtifactModel, ThreatModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";

/**
 * Lấy danh sách tất cả các mối đe dọa (threats) từ cơ sở dữ liệu.
 */
export async function getAll(req: Request, res: Response) {
  try {
    const threats = await ThreatModel.find();
    return res.json(successResponse(threats, "Threats retrieved successfully"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Tạo một mối đe dọa mới nếu nó chưa tồn tại trong cơ sở dữ liệu.
 */
export async function create(req: Request, res: Response) {
  const { data } = req.body;
  try {
    // Kiểm tra xem threat đã tồn tại hay chưa dựa trên tên
    const threat = await ThreatModel.findOne({ name: data.name });
    if (threat) {
      return res.json(errorResponse(`Threat already exists`));
    }

    // Nếu chưa tồn tại, tạo mới threat trong database
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

/**
 * Lấy thông tin của một threat dựa trên ID.
 */
export async function get(req: Request, res: Response) {
  const { id } = req.params;

  // Validate the ID format
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json(errorResponse("Invalid threat ID format"));
  }

  try {
    // Directly query ThreatModel by ID
    const threat = await ThreatModel.findById(id);

    if (!threat) {
      return res.status(404).json(errorResponse("Threat not found"));
    }

    return res.json(successResponse(threat, "Threat retrieved successfully"));
  } catch (error) {
    console.error(`Error retrieving threat with ID ${id}:`, error);
    return res.status(500).json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Cập nhật trạng thái (status) và biện pháp giảm thiểu (mitigation) của một threat.
 */
export async function update(req: Request, res: Response) {
  const { data } = req.body;
  const { status, mitigation } = data;
  const { id } = req.params;
  try {
    // Directly update the threat in ThreatModel
    const updatedThreat = await ThreatModel.findByIdAndUpdate(
      id,
      { status, mitigation },
      { new: true }
    );

    if (!updatedThreat) {
      return res.json(errorResponse("Threat not found"));
    }

    return res.json(successResponse(null, "Threat updated successfully"));
  } catch (error) {
    console.error(`Error updating threat with ID ${id}:`, error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
