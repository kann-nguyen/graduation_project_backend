import { isDocumentArray } from "@typegoose/typegoose";
import { Request, Response } from "express";
import { ArtifactModel, ProjectModel, ThreatModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";

// Lấy tất cả artifacts thuộc về một project cụ thể
export async function getAll(req: Request, res: Response) {
  const { projectName } = req.query;
  try {
    // Tìm project theo tên và populate danh sách phase cùng artifacts của nó
    const project = await ProjectModel.findOne({
      name: projectName,
    }).populate({
      path: "phaseList",
      populate: {
        path: "artifacts",
      },
    });
    
    // Nếu không tìm thấy project, trả về lỗi
    if (!project) {
      return res.json(errorResponse("Project not found"));
    }
    
    // Kiểm tra nếu phaseList là một mảng tài liệu hợp lệ
    if (isDocumentArray(project.phaseList)) {
      // Lấy tất cả artifacts từ các phase
      const artifacts = project.phaseList
        .map((phase) => phase.artifacts)
        .flat();
      
      // Trả về danh sách artifacts kèm theo thông báo thành công
      return res.json(
        successResponse(
          artifacts,
          "Get all artifacts with respective vulnerabilities"
        )
      );
    }
  } catch (error) {
    // Xử lý lỗi nếu có vấn đề trong quá trình lấy dữ liệu
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

// Lấy một artifact cụ thể dựa trên ID
export async function get(req: Request, res: Response) {
  const { id } = req.params;
  try {
    // Tìm artifact theo ID
    const artifact = await ArtifactModel.findById(id);
    
    // Trả về artifact nếu tìm thấy
    return res.json(successResponse(artifact, "Artifact fetched successfully"));
  } catch (error) {
    // Xử lý lỗi nếu có
    return res.json(error);
  }
}

// Cập nhật artifact với dữ liệu mới và danh sách threats
export async function update(req: Request, res: Response) {
  const { id } = req.params;
  const { data } = req.body;
  const { threatList } = data; // Danh sách tên các threat
  try {
    // Tìm danh sách các threat trong database dựa trên tên
    const threats = await ThreatModel.find({ name: { $in: threatList } });
    
    // Cập nhật artifact với dữ liệu mới và danh sách threats
    const artifact = await ArtifactModel.findByIdAndUpdate(
      id,
      {
        ...data,
        threatList: threats, // Gán danh sách threats vào artifact
      },
      {
        new: true, // Trả về artifact sau khi đã cập nhật
      }
    );
    
    // Trả về artifact sau khi cập nhật thành công
    return res.json(successResponse(artifact, "Artifact updated successfully"));
  } catch (error) {
    // Xử lý lỗi nếu có vấn đề trong quá trình cập nhật
    return res.json(error);
  }
}


