import { Request, Response } from "express";
import { ChangeHistoryModel, TicketModel, UserModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";

/**
 * Lấy tất cả ticket của một dự án
 * @param {Request} req - Request từ client, chứa projectName trong query
 * @param {Response} res - Response chứa danh sách ticket hoặc lỗi
 * @returns {Promise<Response>} - Trả về JSON response
 */
export async function getAll(req: Request, res: Response) {
  const { projectName } = req.query;
  if (!projectName) {
    return res.json(errorResponse("Project name is required"));
  }
  try {
    const tickets = await TicketModel.find({ projectName }).populate({
      path: "assignee assigner",
    });
    return res.json(successResponse(tickets, "Tickets fetched successfully"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}


/**
 * Lấy thông tin chi tiết của một ticket
 * @param {Request} req - Request từ client, chứa id của ticket trong params
 * @param {Response} res - Response chứa thông tin ticket hoặc lỗi
 * @returns {Promise<Response>} - Trả về JSON response
 */
export async function get(req: Request, res: Response) {
  const { id } = req.params;
  try {
    const ticket = await TicketModel.findById(id).populate({
      path: "assignee assigner targetedVulnerability",
    });
    if (ticket) {
      return res.json(successResponse(ticket, "Ticket fetched successfully"));
    } else {
      return res.json(errorResponse("Ticket does not exist"));
    }
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Tạo một ticket mới
 * @param {Request} req - Request từ client, chứa dữ liệu ticket trong body
 * @param {Response} res - Response xác nhận tạo thành công hoặc lỗi
 * @returns {Promise<Response>} - Trả về JSON response
 */
export async function create(req: Request, res: Response) {
  const { data } = req.body;
  try {
    // Lấy thông tin người giao và người nhận công việc
    const assigner = await UserModel.findOne({ account: req.user?._id });
    
    let assigneeId = data.assignee;
    // Nếu không có assignee, gợi ý thành viên phù hợp dựa trên threat type
    if (!assigneeId && data.targetedVulnerability?.length > 0 && assigner?.projectIn?.[0]) {
      const threatTypes = data.targetedVulnerability.map((vul: any) => vul.severity);
      const projectId = assigner.projectIn[0].toString(); // ✅ ép kiểu sang string
      const suggested = await suggestAssigneeFromThreatType(projectId, threatTypes);
      assigneeId = suggested?._id;
    }

    
    // Tạo ticket mới và liên kết với người giao, người nhận
    const ticket = await TicketModel.create({
      ...data,
      assignee: assigneeId,
      assigner: assigner?._id,
    });
    
    // // Cập nhật danh sách công việc được giao của người nhận
    // await UserModel.findByIdAndUpdate(data.assignee, {
    //   $push: {
    //     ticketAssigned: ticket._id,
    //   },
    // });
    
    // Ghi lại lịch sử thay đổi
    await ChangeHistoryModel.create({
      objectId: ticket._id,
      action: "create",
      timestamp: ticket.createdAt,
      account: req.user?._id,
      description: `${req.user?.username} created this ticket`,
    });
    return res.json(successResponse(null, "Ticket created successfully"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}


export async function suggestAssigneeFromThreatType(projectId: string, threatTypes: string[]) {
  const members = await UserModel.find({ projectIn: projectId });

  for (const member of members) {
    if (!member.skills) continue;
    if (threatTypes.some((type) => member.skills.includes(type))) {
      return member;
    }
  }

  return null; // Không tìm thấy phù hợp
}

/**
 * Cập nhật thông tin của một ticket
 * @param {Request} req - Request từ client, chứa id của ticket trong params và dữ liệu cập nhật trong body
 * @param {Response} res - Response xác nhận cập nhật thành công hoặc lỗi
 * @returns {Promise<Response>} - Trả về JSON response
 */
export async function update(req: Request, res: Response) {
  const { id } = req.params;
  const { data } = req.body;
  try {
    // Tìm và cập nhật ticket
    const ticket = await TicketModel.findByIdAndUpdate(id, data, { new: true });
    if (ticket) {
      // Ghi lại lịch sử thay đổi, bao gồm trạng thái đóng/mở ticket
      await ChangeHistoryModel.create({
        objectId: ticket._id,
        action: "update",
        timestamp: ticket.updatedAt,
        account: req.user?._id,
        description:
          data.status === "closed"
            ? `${req.user?.username} closed this ticket`
            : `${req.user?.username} reopened this ticket`,
      });
      return res.json(successResponse(null, "Ticket updated successfully"));
    }
    return res.json(errorResponse("Ticket does not exist"));
  } catch (error) {
    console.log(error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}