import { Request, Response } from "express";
import { ArtifactModel, ChangeHistoryModel, ProjectModel, ThreatModel, TicketModel, UserModel } from "../models/models";
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
  try {
    const user = await UserModel.findById("67f286bd35b165dc0adadacf");
    if (!user) {
      return res.status(400).json({ success: false, message: "Assigner not found" });
    }

    let assigneeId = data.assignee && data.assignee.trim().length > 0 ? data.assignee : undefined;
    let submit = true;

    if (!assigneeId && data.targetedThreat && user.projectIn?.[0]) {
      const threat = await ThreatModel.findById(data.targetedThreat);
      if (threat) {
        const projectId = user.projectIn[0].toString();
        const suggested = await suggestAssigneeFromThreatType(projectId, threat.type);
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
      assigner: user._id,
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

export async function autoCreateTicketFromThreat(artifactId: any, threatId: any) {
  try {
    const threat = await ThreatModel.findById(threatId);
    const artifact = await ArtifactModel.findById(artifactId);

    if (!threat) {
      console.error(`❌ Threat with ID ${threatId} not found.`);
      return;
    }

    if (!artifact) {
      console.error(`❌ Artifact with ID ${artifactId} not found.`);
      return;
    }

    const priorityMap: Record<string, "low" | "medium" | "high"> = {
      Spoofing: "low",
      Tampering: "medium",
      Repudiation: "medium",
      "Information Disclosure": "medium",
      "Denial of Service": "high",
      "Elevation of Privilege": "high",
    };

    const priority = priorityMap[threat.type] || "low";

    const suggested = await suggestAssigneeFromThreatType(artifact.projectId.toString(), threat.type);
    const project = await ProjectModel.findById(artifact.projectId);

    const ticket = await TicketModel.create({
      title: `Ticket for Threat ${threat.name}`,
      description: `Automatically generated ticket for ${threat.name} threats.`,
      assignee: suggested ? suggested._id : null,
      assigner: null,
      artifactId: artifactId,
      projectName: project?.name || "Unknown Project",
      targetedThreat: threatId,
      status: "Not accepted",
      priority: priority,
    });

  } catch (error) {
    if (error instanceof Error) {
      console.error(`❌ Error in autoCreateTicketFromThreat: ${error.message}`);
    } else {
      console.error(`❌ Error in autoCreateTicketFromThreat: ${String(error)}`);
    }
  }
}


export async function updateState(req: Request, res: Response) {
  const { data } = req.body;
  const ticketId = req.params.id;
  const user = await UserModel.findById("67f286bd35b165dc0adadacf");

  try {
    const ticket = await TicketModel.findOneAndUpdate(
      { _id: ticketId },
      {
        $set: {
          status: data.status,
          assigner: user
        }
      },
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



export async function suggestAssigneeFromThreatType(projectId: string, threatType: string) {
  try {
    console.log(`🔍 [suggestAssigneeFromThreatType] Searching for assignees in project: ${projectId} for threat type: ${threatType}`);

    // Fetch all members in the project
    const members = await UserModel.find({ projectIn: projectId });

    for (const member of members) {

      if (!member.skills) {
        continue;
      }
      if (member.skills.includes(threatType)) {
        return member;
      }
    }
    return null;
  } catch (error) {
    if (error instanceof Error) {
      console.error(`❌ [suggestAssigneeFromThreatType] Error: ${error.message}`);
    } else {
      console.error(`❌ [suggestAssigneeFromThreatType] Error: ${String(error)}`);
    }
    return null;
  }
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

  export async function testAutoCreateTickets(req: Request, res: Response) {
    const { artifactId } = req.body;
  
    try {
      const artifact = await ArtifactModel.findById(artifactId).populate("threatList");
      if (!artifact) {
        return res.status(404).json({ success: false, message: "Artifact not found" });
      }
  
      if (!artifact.threatList || artifact.threatList.length === 0) {
        return res.status(400).json({ success: false, message: "No threats found in the artifact" });
      }

      
      for (const threat of artifact.threatList) {
        await autoCreateTicketFromThreat(artifactId, threat._id);
      }
  
      return res.status(200).json({ success: true, message: "Tickets created successfully" });
    } catch (error) {
      console.error(`❌ Error in testAutoCreateTickets: ${error}`);
      return res.status(500).json({ success: false, message: "Internal server error" });
    }
  }