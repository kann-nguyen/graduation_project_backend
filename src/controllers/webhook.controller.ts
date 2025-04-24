import { Request, Response } from "express";
import { ArtifactModel, ThreatModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";

import { processScannerResult } from "./artifact.controller";

// Định nghĩa kiểu dữ liệu cho body request
interface RequestBody {
  eventCode: string;
  imageName: string;
  securityState: string,
  data: Array<{
    cveId: string;
    description: string;
    severity: string;
    score?: number;
  }>;
}

// Định nghĩa kiểu dữ liệu cho body request
interface DocsRequestBody {
  eventCode: string;
  artifact_id: string;
  securityState: string,
  data: {
    hasSensitiveData: boolean;
    policyCompliant: boolean;
  };
}


/**
 * Import danh sách lỗ hổng bảo mật (vulnerabilities) vào một artifact hình ảnh
 * @param {Request} req - Request từ client, chứa thông tin về hình ảnh và danh sách lỗ hổng
 * @param {Response} res - Response xác nhận import thành công hoặc lỗi
 * @returns {Promise<Response>} - Trả về JSON response
 */
export async function importVulnToImage(req: Request, res: Response) {
  const { eventCode, imageName, securityState, data }: RequestBody = req.body;

  try {
    console.log("Received request:", { eventCode, imageName, securityState });

    const [name, version] = imageName.split(":");
    const artifacts = await ArtifactModel.find({ name, version });

    if (!artifacts || artifacts.length === 0) {
      return res.json(
        errorResponse(`No artifact found with name ${name} and version ${version}`)
      );
    }

    for (const artifact of artifacts) {
      processScannerResult(artifact._id.toString(), data);
    }

  } catch (error) {
    console.error("Error during importVulnToImage:", error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}


export async function importVulnToDocs(req: Request, res: Response) {
  const { eventCode, artifact_id, securityState, data }: DocsRequestBody = req.body;
  try {
    // Tìm các artifact có cùng tên và phiên bản
    const artifacts = await ArtifactModel.find({artifact_id});
    
    // Kiểm tra nếu không tìm thấy artifact phù hợp
    if (!artifacts) {
      return res.json(
        errorResponse(
          `No artifact found with id ${artifact_id}`
        )
      );
    }
    
    // Cập nhật danh sách vulnerabilities cho các artifact tìm thấy
    await ArtifactModel.updateMany(
      { artifact_id },
      {
        $set: {
          state: securityState
        },
      }
    );
    
    return res.json(
      successResponse(null, "Successfully imported vulnerabilities")
    );
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

