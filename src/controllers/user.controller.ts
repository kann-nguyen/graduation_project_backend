import { Request, Response } from "express";
import { AccountModel, UserModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";

/**
 * Lấy thông tin người dùng bằng memberId hoặc accountId
 * @param {Request} req - Request từ client, chứa memberId hoặc accountId trong query
 * @param {Response} res - Response chứa thông tin người dùng hoặc lỗi
 * @returns {Promise<Response>} - Trả về JSON response
 */
export async function get(req: Request, res: Response) {
  const { memberId, accountId } = req.query;
  try {
    if (memberId) {
      const user = await UserModel.findById(memberId).populate({
        path: "activityHistory taskAssigned ticketAssigned account",
      });
      return res.json(successResponse(user, "User found"));
    }
    if (accountId) {
      const user = await UserModel.findOne({ account: accountId }).populate({
        path: "activityHistory taskAssigned ticketAssigned account",
      });
      return res.json(successResponse(user, "User found"));
    }
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Tạo người dùng mới
 * @param {Request} req - Request từ client, chứa dữ liệu người dùng trong body
 * @param {Response} res - Response xác nhận tạo thành công hoặc lỗi
 * @returns {Promise<Response>} - Trả về JSON response
 */
export async function create(req: Request, res: Response) {
  try {
    const user = await UserModel.create(req.body);
    return res.json(successResponse(null, "User created"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Cập nhật thông tin người dùng
 * @param {Request} req - Request từ client, chứa thông tin cập nhật trong body
 * @param {Response} res - Response xác nhận cập nhật thành công hoặc lỗi
 * @returns {Promise<Response>} - Trả về JSON response
 */
export async function update(req: Request, res: Response) {
  const account = req.user;
  const { name, email } = req.body;
  if (!account) return res.json(errorResponse("You are not authenticated"));
  try {
    await AccountModel.findByIdAndUpdate(account._id, { email });
    await UserModel.findOneAndUpdate({ account: account._id }, { name });
    return res.json(successResponse(null, "Info updated"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Xóa người dùng
 * @param {Request} req - Request từ client, chứa id của người dùng trong params
 * @param {Response} res - Response xác nhận xóa thành công hoặc lỗi
 * @returns {Promise<Response>} - Trả về JSON response
 */
export async function remove(req: Request, res: Response) {
  const { id } = req.params;
  try {
    await UserModel.findByIdAndDelete(id);
    return res.json(successResponse(null, "User deleted"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Gán một task cho người dùng
 * @param {Request} req - Request từ client, chứa id của người dùng và taskId trong params
 * @param {Response} res - Response xác nhận gán task thành công hoặc lỗi
 * @returns {Promise<Response>} - Trả về JSON response
 */
export async function assignTask(req: Request, res: Response) {
  const { id, taskId } = req.params;
  try {
    // Kiểm tra xem task đã được gán chưa, nếu chưa thì thêm vào danh sách taskAssigned
    const user = await UserModel.findByIdAndUpdate(
      id,
      { $addToSet: { taskAssigned: taskId } },
      { new: true }
    );
    return res.json(successResponse(null, "Task assigned"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Thêm người dùng vào một dự án
 * @param {Request} req - Request từ client, chứa id của người dùng trong params và projectId trong body
 * @param {Response} res - Response xác nhận thêm thành công hoặc lỗi
 * @returns {Promise<Response>} - Trả về JSON response
 */
export async function addProjectIn(req: Request, res: Response) {
  const { id } = req.params;
  const { projectId } = req.body;
  try {
    // Thêm projectId vào danh sách projectIn của người dùng, tránh trùng lặp
    const user = await UserModel.findByIdAndUpdate(
      id,
      { $addToSet: { projectIn: projectId } },
      { new: true }
    );
    return res.json(successResponse(null, "Project added to user"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Lấy danh sách dự án mà người dùng đang tham gia
 * @param {Request} req - Request từ client, lấy id từ tài khoản người dùng hiện tại
 * @param {Response} res - Response chứa danh sách dự án hoặc lỗi
 * @returns {Promise<Response>} - Trả về JSON response
 */
export async function getProjectIn(req: Request, res: Response) {
  const account = req.user;
  if (!account) return res.json(errorResponse("Not logged in"));
  const id = account._id;
  try {
    // Lấy thông tin người dùng và populate danh sách dự án họ tham gia
    const user = await UserModel.findOne({ account: id }).populate("projectIn");
    if (!user) {
      return res.json(errorResponse("User not found"));
    }
    const data = user.projectIn;
    return res.json(successResponse(data, "List of projects fetched"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Lấy danh sách tất cả người dùng
 * @param {Request} req - Request từ client
 * @param {Response} res - Response chứa danh sách người dùng hoặc lỗi
 * @returns {Promise<Response>} - Trả về JSON response
 */
export async function getAllUsers(req: Request, res: Response) {
  try {
    // Lấy tất cả người dùng và populate thông tin tài khoản liên kết
    const users = await UserModel.find().populate({
      path: "account",
    });
    return res.json(successResponse(users, "List of users fetched"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Admin-specific user update function with skills management
 * @param {Request} req - Request from admin containing user updates
 * @param {Response} res - Response confirming update success or error
 * @returns {Promise<Response>} - JSON response
 */
export async function adminUpdateUser(req: Request, res: Response) {
  const { id } = req.params;
  const { name, skills } = req.body;
  
  try {
    // Update user data including skills
    const updatedUser = await UserModel.findByIdAndUpdate(
      id,
      { 
        ...(name && { name }),
        ...(skills && { skills })
      },
      { new: true }
    ).populate("account");
    
    if (!updatedUser) {
      return res.json(errorResponse("User not found"));
    }
    
    return res.json(successResponse(updatedUser, "User updated successfully"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
