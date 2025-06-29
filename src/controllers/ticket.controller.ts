import { Request, Response } from "express";
import { AccountModel, ArtifactModel, ChangeHistoryModel, PhaseModel, ProjectModel, ThreatModel, TicketModel, UserModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import { scanArtifact } from "./phase.controller";
import { ArtifactWorkflowController } from "./artifactWorkflow.controller";

/**
 * Lấy tất cả ticket của một dự án
 * @param {Request} req - Request từ client, chứa projectName trong query
 * @param {Response} res - Response chứa danh sách ticket hoặc lỗi
 * @returns {Promise<Response>} - Trả về JSON response
 */
export async function getAll(req: Request, res: Response) {
  const { projectName } = req.query;
  const accountId = req.user?._id;

  if (!projectName) {
    return res.json(errorResponse("Project name is required"));
  }

  try {
    // Lấy thông tin user và account để kiểm tra quyền
    const user = await UserModel.findOne({ account: accountId });
    if (!user) {
      return res.json(errorResponse("User not found"));
    }

    const account = await AccountModel.findById(user.account);
    if (!account) {
      return res.json(errorResponse("Account not found"));
    }

    // Tạo query cơ bản cho tickets
    let query: { projectName: string; assignee?: string; status?: { $nin?: string[] } } = { 
      projectName: projectName as string 
    };
    
    if (account.role === "member") {
      // Member thường chỉ có thể xem tickets được gán cho họ
      query.assignee = user._id.toString();
      query.status = { $nin: ["Not accepted", "Resolved"] };
    }

    const tickets = await TicketModel.find(query).populate({
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
      path: "assignee assigner targetedThreat",
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
  const accountId = req.user?._id;
  let user = null
  try {
    if(accountId) {
      user = await UserModel.findOne({
        account: accountId,
      });
    } 

    if (!user) {
      return res.json(errorResponse("User not found"));
    }

    let assigneeId = data.assignee && data.assignee.trim().length > 0 ? data.assignee : undefined;
    let submit = true;

    if (!assigneeId && data.targetedThreat && 'projectIn' in user && user.projectIn?.[0]) {
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

    // Đặt trạng thái ban đầu và đảm bảo previousStatus giống với trạng thái ban đầu
    const initialStatus = data.status || "Not accepted";
    
    const ticket = await TicketModel.create({
      ...data,
      targetedThreat: data.targetedThreat,
      assignee: assigneeId,
      assigner: user._id,
      status: initialStatus,
      previousStatus: initialStatus // Đặt previousStatus giống với trạng thái ban đầu
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

    return res.json(successResponse(ticket, "Ticket created successfully"));
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return res.json(errorResponse(`Internal server error: ${errorMessage}`));
  }
}

/**
 * Tự động tạo ticket từ threat
 * @param artifactId - ID của artifact
 * @param threatId - ID của threat
 */
export async function autoCreateTicketFromThreat(artifactId: any, threatId: any) {
  try {
    const threat = await ThreatModel.findById(threatId);
    const artifact = await ArtifactModel.findById(artifactId);

    if (!threat) {
      return;
    }

    if (!artifact) {
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

    // Đặt trạng thái ban đầu cho tickets tự động tạo
    const initialStatus = "Not accepted";

    const ticket = await TicketModel.create({
      title: `Ticket for Threat ${threat.name}`,
      description: `Automatically generated ticket for ${threat.name} threats.`,
      assignee: suggested ? suggested._id : null,
      assigner: null,
      artifactId: artifactId,
      projectName: project?.name || "Unknown Project",
      targetedThreat: threatId,
      status: initialStatus,
      previousStatus: initialStatus, // Đặt previousStatus giống với trạng thái ban đầu
      priority: priority,
    });

    await ChangeHistoryModel.create({
      objectId: ticket._id,
      action: "create",
      timestamp: ticket.createdAt,
      account: null,
      description: `Ticket automatically created for threat ${threat.name}`,
    });

  } catch (error) {
    // Xử lý lỗi nhưng không log ra console
  }
}


/**
 * Cập nhật trạng thái ticket
 * @param req - Express request
 * @param res - Express response
 */
export async function updateState(req: Request, res: Response) {
  const { data } = req.body;
  const ticketId = req.params.id;
  const userId = req.user?._id

  try {
    // Tìm ticket trước để kiểm tra trạng thái hiện tại
    const currentTicket = await TicketModel.findById(ticketId).populate('assignee');

    if (!currentTicket) {
      return res.json(errorResponse("Ticket not found"));
    }

    // Lấy thông tin user thực hiện request
    const user = await UserModel.findOne({
      account: userId,
    });

    if (!user) {
      return res.json(errorResponse("User not found"));
    }

    const account = await AccountModel.findById(user.account);

    if (!account) {
      return res.json(errorResponse("Account not found"));
    }

    

    if (currentTicket.status === "Not accepted" && data.status === "Processing") {
      // Cho phép cả project_manager và security_expert thay đổi ticket sang trạng thái Processing
      if (account.role !== "security_expert") {
        return res.json(errorResponse("Only security experts can change ticket to Processing state"));
      }
    } else if (currentTicket.status === "Processing" && data.status === "Submitted") {
      if (currentTicket.assignee?._id.toString() !== user._id.toString()) {
        return res.json(errorResponse("Only the assigned user can change ticket to Submitted state"));
      }
    } else {
      return res.json(errorResponse("Invalid status transition"));
    }

    // Lưu trạng thái hiện tại làm previousStatus trước khi cập nhật
    const previousStatus = currentTicket.status;

    // Cập nhật ticket nếu kiểm tra quyền thành công
    const ticket = await TicketModel.findOneAndUpdate(
      { _id: ticketId },
      {
        $set: {
          status: data.status,
          previousStatus: previousStatus // Lưu trạng thái trước đó
        }
      },
      { new: true }
    ).populate('assignee');

    if (!ticket) {
      return res.json(errorResponse("Ticket not found after update"));
    }

    const artifact = await ArtifactModel.findById(ticket.artifactId);

    if (!artifact) {
      return;
    } 

    // Xử lý các hành động sau khi cập nhật
    switch (ticket.status) {
      case "Processing":
        // Tìm user được phân công trước
        const assignee = await UserModel.findById(ticket.assignee?._id);
        
        // Cập nhật mảng ticketAssigned của assignee
        if (assignee) {
          await UserModel.findByIdAndUpdate(assignee._id, {
            $addToSet: { // Sử dụng addToSet để tránh trùng lặp
              ticketAssigned: ticket._id
            },
          });
        }
        
        // Cập nhật ticket với thông tin assigner
        await TicketModel.findOneAndUpdate(
          { _id: ticketId },
          {
            $set: {
              status: data.status,
              assigner: user._id
            }
          }
        );
        
        // Cập nhật trạng thái workflow vì ticket đã được gán
        try {
          await ArtifactWorkflowController.updateWorkflowStatus(artifact._id, 3);
        } catch (workflowError) {
          // Không throw lỗi ở đây vì không muốn chặn việc cập nhật ticket
        }
        
        // Tạo entry lịch sử với tên đúng
        const assigneeName = assignee?.name || 'Unknown';
        
        await ChangeHistoryModel.create({
          objectId: ticket._id, 
          action: "update",
          timestamp: new Date(),
          account: user._id,
          description: `${user.name} assigned ticket to ${assigneeName}`,
        });
        break;

      case "Submitted":
        // Lấy tên assignee từ ticket đã populate
        const submitterName = (ticket.assignee && typeof ticket.assignee !== 'string' && 'name' in ticket.assignee ? ticket.assignee.name : user.name);
        
        handleTicketSubmitted(ticket._id.toString());

        // Cập nhật trạng thái workflow vì ticket đã được submit
        try {
          await ArtifactWorkflowController.updateWorkflowStatus(artifact._id, 4);
        } catch (workflowError) {
          // Không throw lỗi ở đây vì không muốn chặn việc cập nhật ticket
        }
        
        await ChangeHistoryModel.create({
          objectId: ticket._id, 
          action: "update",
          timestamp: new Date(),
          account: user._id,
          description: `${submitterName} submitted ticket`,
        });
        break;
    }

    return res.json(successResponse(null, `Ticket status changed to: ${ticket.status} successfully`));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Cập nhật trạng thái ticket liên quan đến một threat
 * Nếu isDone = true: cập nhật ticket thành "Resolved"
 * Nếu false: cập nhật ticket thành "Processing"
 * @param threatId - ID của threat
 * @param isDone - Trạng thái hoàn thành
 */
export async function updateTicketStatusForThreat(threatId: any, isDone: boolean) {
  // Tìm ticket liên kết với threat này
  const ticket = await TicketModel.findOne({ targetedThreat: threatId }).populate({
    path: "assignee targetedThreat",
  });
  
  if (!ticket) {
    return;
  }

  if (ticket.status === "Submitted") {
    const newStatus = isDone ? "Resolved" : "Processing";

    // Lưu trạng thái hiện tại làm previousStatus trước khi cập nhật
    const previousStatus = ticket.status;

    // Cập nhật trạng thái ticket
    const updatedTicket = await TicketModel.findByIdAndUpdate(
      ticket._id, 
      { $set: { 
          status: newStatus, 
          previousStatus: previousStatus  // Đặt previousStatus
        } 
      },
      { new: true }
    );

    if (!updatedTicket) {
      return;
    }

    // Lấy tên threat để ghi lịch sử tốt hơn
    const threatName = (ticket.targetedThreat && typeof ticket.targetedThreat !== 'string' && 'name' in ticket.targetedThreat)
      ? ticket.targetedThreat.name
      : "unknown threat";
      
    // Ghi lại lịch sử thay đổi với mô tả tốt hơn
    let description = "";
    if (isDone) {
      description = `Verified success and resolved ticket`;
    } else {
      description = `Verified failed and returned ticket to processing`;
    }

    await ChangeHistoryModel.create({
      objectId: ticket._id,
      action: "update",
      timestamp: new Date(), // Sử dụng thời gian hiện tại thay vì ticket.updatedAt để có timestamp chính xác
      account: null,
      description: description
    });
  }
}

/**
 * Đề xuất assignee từ loại threat
 * @param projectId - ID của project
 * @param threatType - Loại threat
 * @returns User phù hợp hoặc null
 */
export async function suggestAssigneeFromThreatType(projectId: string, threatType: string) {
  try {
    // Lấy tất cả members trong project
    const members = await UserModel.find({ projectIn: projectId });

    for (const member of members) {
      // Kiểm tra xem mảng skills có tồn tại và là array trước khi sử dụng includes()
      if (!member.skills || !Array.isArray(member.skills)) {
        continue;
      }
      
      if (member.skills.includes(threatType)) {
        return member;
      }
    }
    return null;
  } catch (error) {
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
      // Lấy ticket gốc trước khi cập nhật
      const originalTicket = await TicketModel.findById(id);
      
      if (!originalTicket) {
        return res.json(errorResponse("Ticket does not exist"));
      }

      // Tìm và cập nhật ticket
      const ticket = await TicketModel.findByIdAndUpdate(id, data, { new: true });
      
      if (ticket) {
        // Xây dựng mô tả thay đổi đơn giản với tên trường
        const changedFields = [];
        
        if (data.title && data.title !== originalTicket.title) {
          changedFields.push("title");
        }
        if (data.description && data.description !== originalTicket.description) {
          changedFields.push("description");
        }
        if (data.assignee && data.assignee !== (originalTicket.assignee?.toString() || null)) {
          changedFields.push("assignee");
        }
        
        // Tạo mô tả chỉ với tên trường
        const changeDescription = `${req.user?.username} updated ticket fields: ${changedFields.join(', ')}`;

        // Ghi lại lịch sử thay đổi
        await ChangeHistoryModel.create({
          objectId: ticket._id,
          action: "update",
          timestamp: ticket.updatedAt,
          account: req.user?._id,
          description: changeDescription
        });
        
        return res.json(successResponse(null, "Ticket updated successfully"));
      }
      
      return res.json(errorResponse("Failed to update ticket"));
    } catch (error) {
      return res.json(errorResponse(`Internal server error: ${error}`));
    }
  }

  /**
   * Xử lý khi ticket được submit
   * @param ticketId - ID của ticket
   */
  async function handleTicketSubmitted(ticketId: string) {
    const ticket = await TicketModel.findById(ticketId).populate("artifactId targetedThreat");

    if (!ticket) {
      return;
    }

    const artifact = await ArtifactModel.findById(ticket.artifactId);

    if (!artifact) {
      return;
    } 
    
    artifact.numberThreatSubmitted = (artifact.numberThreatSubmitted || 0) + 1;
    await artifact.save();

    // Kiểm tra tỷ lệ threat đã submit
    const totalThreat = artifact.threatList?.length || 0;
    const submittedRatio = totalThreat > 0 ? (artifact.numberThreatSubmitted || 0) / totalThreat * 100 : 0;

    const managerConfigThreshold = artifact.rateReScan || 50;

    if (submittedRatio >= managerConfigThreshold && (artifact.totalScanners ?? 0) <= 0) {
      // Tìm phase chứa artifact này
      const phase = await PhaseModel.findOne({ artifacts: artifact._id });
      if (!phase) {
        return;
      }

      // Cập nhật totalScanners để ngăn quét nhiều lần
      await ArtifactModel.findByIdAndUpdate(artifact._id, { 
        $set: { totalScanners: 1 } 
      });

      // Kích hoạt quét lại artifact với phase ID thật
      setImmediate(async () => {
        try {
          await scanArtifact(artifact, phase._id.toString());
        } catch (error) {
          // Reset totalScanners khi thất bại
          await ArtifactModel.findByIdAndUpdate(artifact._id, { 
            $set: { totalScanners: 0 } 
          });
        }
      });
    }
  }