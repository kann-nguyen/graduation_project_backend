import { Request, Response } from "express";
import { ArtifactModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";

// Định nghĩa kiểu dữ liệu cho body request
interface RequestBody {
  eventCode: string;
  imageName: string;
  data: Array<{
    cveId: string;
    description: string;
    severity: string;
    score?: number;
  }>;
}

/**
 * Import danh sách lỗ hổng bảo mật (vulnerabilities) vào một artifact hình ảnh
 * @param {Request} req - Request từ client, chứa thông tin về hình ảnh và danh sách lỗ hổng
 * @param {Response} res - Response xác nhận import thành công hoặc lỗi
 * @returns {Promise<Response>} - Trả về JSON response
 */
export async function importVulnToImage(req: Request, res: Response) {
  const { eventCode, imageName, data }: RequestBody = req.body;
  try {
    // Phân tách tên image và version từ chuỗi imageName có dạng {image}:{tag} hoặc {author}/{image}:{tag}
    const name = imageName.split(":")[0];
    const version = imageName.split(":")[1];
    
    // Tìm các artifact có cùng tên và phiên bản
    const artifacts = await ArtifactModel.find({ name, version });
    
    // Kiểm tra nếu không tìm thấy artifact phù hợp
    if (!artifacts) {
      return res.json(
        errorResponse(
          `No artifact found with name ${name} and version ${version}`
        )
      );
    }
    
    // Cập nhật danh sách vulnerabilities cho các artifact tìm thấy
    await ArtifactModel.updateMany(
      { name, version },
      {
        $set: {
          vulnerabilityList: data,
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
