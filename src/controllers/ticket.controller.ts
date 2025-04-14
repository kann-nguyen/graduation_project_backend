import { Request, Response } from "express";
import { ArtifactModel, ChangeHistoryModel, ThreatModel, TicketModel, UserModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import { boolean } from "zod";

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
  const user = await UserModel.findById("67f286bd35b165dc0adadacf");
  try {
    const assigner = user;
    if (!assigner) {
      return res.status(400).json({ success: false, message: "Assigner not found" });
    }

    let assigneeId = data.assignee && data.assignee.trim().length > 0 ? data.assignee : undefined;
    let submit = true;

    if (!assigneeId && data.targetedThreat && assigner?.projectIn?.[0]) {
      const threat = await ThreatModel.findById(data.targetedThreat);
      if (threat) {
        const projectId = assigner.projectIn[0].toString();
        const suggested = await suggestAssigneeFromThreatType(projectId, [threat.type]);
        if (suggested) {
          assigneeId = suggested._id;
          submit = false;
        } 
      } 
    }

    const ticket = await TicketModel.create({
      ...data,
      targetedThreat: data.targetedThreat,
      assignee: assigneeId,
      assigner: assigner._id,
    });

    if (submit && data.assignee && data.assignee.trim().length > 0) {
      await UserModel.findByIdAndUpdate(data.assignee, {
        $push: { ticketAssigned: ticket._id },
      });
    }

    await ChangeHistoryModel.create({
      objectId: ticket._id,
      action: "create",
      timestamp: ticket.createdAt,
      account: user._id,
      description: `${user.name} created this ticket`,
    });

    return res.json({ success: true, message: "Ticket created successfully" });

  } catch (error) {
    return res.json({ success: false, message: `Internal server error: ${error}` });
  }
}


export async function updateState(req: Request, res: Response) {
  const { data } = req.body;
  const ticketId = req.params.id;

  try {
    const ticket = await TicketModel.findOneAndUpdate(
      { _id: ticketId },
      { $set: { status: data.status } },
      { new: true }
    );

    if (!ticket) {
      return res.json(successResponse(null, `Invalid ticket`));
    }

    switch (ticket.status) {
      case "Processing":
        await UserModel.findByIdAndUpdate(ticket.assignee, {
          $push: {
            ticketAssigned: ticket._id,
          },
        });
        break;

      case "Submitted":
        handleTicketSubmitted(ticket._id.toString());
        break;

      default:
        console.log(`ℹ️ [updateState] No specific action defined for status: "${ticket.status}"`);
    }

    // Optional change history (uncomment if needed)
    /*
    await ChangeHistoryModel.create({
      objectId: ticket._id,
      action: "update",
      timestamp: new Date(),
      account: req.user?._id,
      description: `${req.user?.username} changed status of ticket "${ticket.title}" to "${ticket.status}"`,
    });
    console.log(`📝 [updateState] ChangeHistory recorded.`);
    */
    return res.json(successResponse(null, "Ticket is changed to: " + ticket.status + " successfully"));
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
        description: `${req.user?.username} change status of this ticket to ` + ticket.status
      });
      return res.json(successResponse(null, "Ticket updated successfully"));
    }
    return res.json(errorResponse("Ticket does not exist"));
  } catch (error) {
    console.log(error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}


async function handleTicketSubmitted(ticketId: string) {
  const ticket = await TicketModel.findById(ticketId).populate("targetArtifact targetedThreat");

  if (!ticket) return;

  const artifact = await ArtifactModel.findById(ticket.artifactId);

  if (!artifact) return;

  // Cộng số lượng threat đã được submit
  artifact.numberThreatSubmitted = (artifact.numberThreatSubmitted || 0) + 1;
  await artifact.save();

  // Check tỷ lệ threat đã submit
  const totalThreat = artifact.threatList?.length || 0;
  const submittedRatio = (artifact.numberThreatSubmitted || 0) / totalThreat;

  const managerConfigThreshold = 0.5; // Ví dụ Manager yêu cầu xử lý 50% threat

  if (submittedRatio >= managerConfigThreshold) {
    // Trigger quét lại artifact
    //const scanResult = await scanArtifact(artifact); // giả lập gọi scanner và trả về danh sách vuln mới
  }
}