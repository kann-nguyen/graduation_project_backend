import { ProjectModel, UserModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import { Request, Response } from "express";

// Đăng xuất người dùng khỏi hệ thống
export async function logout(req: Request, res: Response) {
  req.logout((err) => {
    if (err) {
      return res.json(errorResponse(err));
    }
  });
  return res.json(successResponse(null, "Logged out"));
}

// Chuyển hướng người dùng đến trang chủ dựa trên project đầu tiên họ tham gia
export async function redirectToHomePage(req: Request, res: Response) {
  const account = req.user;
  if (!account) return;
  try {
    // Tìm user theo account ID
    const user = await UserModel.findOne({ account: account._id });
    const firstProject = user?.projectIn[0];
    
    // Nếu user có project đầu tiên, tìm project và chuyển hướng đến trang của nó
    if (firstProject) {
      const project = await ProjectModel.findById(firstProject);
      if (project) {
        const urlEncodedName = encodeURIComponent(project.name);
        // Use CLIENT_URL from environment variable instead of hardcoded value
        return res.redirect(`${process.env.CLIENT_URL}/${urlEncodedName}/`);
      }
    }
  } catch (err) {
    return res.json(errorResponse("Error redirecting to home page"));
  }
  
  // Nếu không có project nào, chuyển hướng đến trang tạo project mới
  // Use CLIENT_URL from environment variable
  return res.redirect(`${process.env.CLIENT_URL}/new-project/`);
}
