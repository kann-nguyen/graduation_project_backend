import { Request, Response } from "express";
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
 * Threat là một phần của danh sách threatList trong ArtifactModel (sub-document).
 */
export async function get(req: Request, res: Response) {
  const { id } = req.params;
  try {
    // Tìm artifact chứa threat có ID tương ứng
    const artifact = await ArtifactModel.findOne({
      threatList: { $elemMatch: { _id: id } },
    });

    // Lọc ra threat có ID khớp trong danh sách threatList của artifact
    const threat = artifact?.threatList?.find((threatId) => threatId.toString() == id);
    if (!threat) {
      return res.json(errorResponse(`Threat not found`));
    }

    return res.json(successResponse(threat, "Threat retrieved successfully"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Cập nhật trạng thái (status) và biện pháp giảm thiểu (mitigation) của một threat.
 * Threat là một phần của danh sách threatList trong ArtifactModel (sub-document).
 */
export async function update(req: Request, res: Response) {
  const { data } = req.body;
  const { status, mitigation } = data;
  const { id } = req.params;
  try {
    // Cập nhật threat trong danh sách threatList của tất cả ArtifactModel chứa threat này
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
