import { Request, Response } from "express";
import { AccountModel, ArtifactModel, ChangeHistoryModel, PhaseModel, ProjectModel, ThreatModel, TicketModel, UserModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import { scanArtifact } from "./phase.controller";

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
    // Get the user and their account to check role
    const user = await UserModel.findOne({ account: accountId });
    if (!user) {
      return res.json(errorResponse("User not found"));
    }

    const account = await AccountModel.findById(user.account);
    if (!account) {
      return res.json(errorResponse("Account not found"));
    }

    // Create base query for tickets
    let query: { projectName: string; assignee?: string; status?: { $nin?: string[] } } = { 
      projectName: projectName as string 
    };
    
    if (account.role === "member") {
      // Regular member can only see tickets assigned to them
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

    return res.json(successResponse(ticket, "Ticket created successfully"));
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    console.error(`❌ Error creating ticket: ${errorMessage}`);
    return res.json(errorResponse(`Internal server error: ${errorMessage}`));
  }
}

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

    await ChangeHistoryModel.create({
      objectId: ticket._id,
      action: "create",
      timestamp: ticket.createdAt,
      account: null,
      description: `Ticket automatically created for threat ${threat.name}`,
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
  const userId = req.user?._id

  try {
    // Find the ticket first to check current status
    const currentTicket = await TicketModel.findById(ticketId).populate('assignee');

    if (!currentTicket) {
      return res.json(errorResponse("Ticket not found"));
    }

    // Get the user making the request
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
      // Allow both project_manager and security_expert to change ticket to Processing state
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

    // Update the ticket if permissions check passed
    const ticket = await TicketModel.findOneAndUpdate(
      { _id: ticketId },
      {
        $set: {
          status: data.status
        }
      },
      { new: true }
    ).populate('assignee');

    if (!ticket) {
      return res.json(errorResponse("Ticket not found after update"));
    }

    // Handle post-update actions
    switch (ticket.status) {
      case "Processing":
        // Find the assigned user first
        const assignee = await UserModel.findById(ticket.assignee?._id);
        
        // Update the assignee's ticketAssigned array
        if (assignee) {
          await UserModel.findByIdAndUpdate(assignee._id, {
            $addToSet: { // Use addToSet to avoid duplicates
              ticketAssigned: ticket._id
            },
          });
        }
        
        // Update ticket with assigner info
        await TicketModel.findOneAndUpdate(
          { _id: ticketId },
          {
            $set: {
              status: data.status,
              assigner: user._id
            }
          }
        );
        
        // Create history entry with proper names
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
        // Get assignee name from populated ticket
        const submitterName = (ticket.assignee && typeof ticket.assignee !== 'string' && 'name' in ticket.assignee ? ticket.assignee.name : user.name);
        
        handleTicketSubmitted(ticket._id.toString());
        
        await ChangeHistoryModel.create({
          objectId: ticket._id, 
          action: "update",
          timestamp: new Date(),
          account: user._id,
          description: `${submitterName} submitted ticket`,
        });
        break;
    }

    console.log('✅ Update completed successfully');
    return res.json(successResponse(null, `Ticket status changed to: ${ticket.status} successfully`));
  } catch (error) {
    console.error('❌ Error updating ticket state:', error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Update the status of a ticket related to a threat.
 * If isDone = true: update ticket to "Resolved",
 * if false: update ticket to "Processing".
 */
export async function updateTicketStatusForThreat(threatId: any, isDone: boolean) {
  // Find ticket linked to this threat
  const ticket = await TicketModel.findOne({ targetedThreat: threatId }).populate({
    path: "assignee targetedThreat",
  });
  
  if (!ticket) {
    console.warn(`No ticket found linked to threat ${threatId}`);
    return;
  }

  if (ticket.status === "Submitted") {
    const newStatus = isDone ? "Resolved" : "Processing";
    console.log(`📝 Updating ticket ${ticket._id} status from ${ticket.status} to ${newStatus}`);

    // Update ticket status
    const updatedTicket = await TicketModel.findByIdAndUpdate(
      ticket._id, 
      { $set: { status: newStatus } },
      { new: true }
    );

    if (!updatedTicket) {
      console.error(`❌ Failed to update ticket ${ticket._id}`);
      return;
    }

    // Get the threat name for better history logs
    const threatName = (ticket.targetedThreat && typeof ticket.targetedThreat !== 'string' && 'name' in ticket.targetedThreat)
      ? ticket.targetedThreat.name
      : "unknown threat";
    
    // Record the change history with better descriptions
    let description = "";
    if (isDone) {
      description = `Verified success and resolved ticket`;
    } else {
      description = `Verified failed and returned ticket to processing`;
    }

    await ChangeHistoryModel.create({
      objectId: ticket._id,
      action: "update",
      timestamp: new Date(), // Use current time instead of ticket.updatedAt for accurate timestamps
      account: null,
      description: description
    });

    // Log the successful status change
    const statusChangeMessage = isDone 
      ? `✅ Successfully resolved ticket ${ticket._id}`
      : `🔄 Returned ticket ${ticket._id} to processing`;
    console.log(statusChangeMessage);
  }
}

export async function suggestAssigneeFromThreatType(projectId: string, threatType: string) {
  try {

    // Fetch all members in the project
    const members = await UserModel.find({ projectIn: projectId });

    for (const member of members) {
      // Check if skills array exists and is an array before using includes()
      if (!member.skills || !Array.isArray(member.skills)) {
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
      // Get the original ticket before updating
      const originalTicket = await TicketModel.findById(id);
      
      if (!originalTicket) {
        return res.json(errorResponse("Ticket does not exist"));
      }

      // Tìm và cập nhật ticket
      const ticket = await TicketModel.findByIdAndUpdate(id, data, { new: true });
      
      if (ticket) {
        // Build a simple change description with field names
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
        
        // Create a description with just the field names
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
      console.log(error);
      return res.json(errorResponse(`Internal server error: ${error}`));
    }
  }

  async function handleTicketSubmitted(ticketId: string) {
    const ticket = await TicketModel.findById(ticketId).populate("artifactId targetedThreat");

    if (!ticket) {
      console.log(`[DEBUG] Ticket ${ticketId} not found`);
      return;
    }

    const artifact = await ArtifactModel.findById(ticket.artifactId);

    if (!artifact) {
      console.log(`[DEBUG] Artifact ${ticket.artifactId} not found`);
      return;
    }

    console.log(`[DEBUG] Processing ticket submission for artifact ${artifact._id}`);
    console.log(`[DEBUG] Current numberThreatSubmitted: ${artifact.numberThreatSubmitted || 0}`);
    console.log(`[DEBUG] Total threats: ${artifact.threatList?.length || 0}`);
    console.log(`[DEBUG] Current totalScanners: ${artifact.totalScanners ?? 0}`);

    // Cộng số lượng threat đã được submit
    artifact.numberThreatSubmitted = (artifact.numberThreatSubmitted || 0) + 1;
    await artifact.save();

    // Check tỷ lệ threat đã submit
    const totalThreat = artifact.threatList?.length || 0;
    const submittedRatio = totalThreat > 0 ? (artifact.numberThreatSubmitted || 0) / totalThreat * 100 : 0;

    const managerConfigThreshold = artifact.rateReScan || 50;
    
    console.log(`[DEBUG] Updated numberThreatSubmitted: ${artifact.numberThreatSubmitted}`);
    console.log(`[DEBUG] Submitted ratio: ${submittedRatio.toFixed(2)}%`);
    console.log(`[DEBUG] Manager threshold: ${managerConfigThreshold}%`);
    console.log(`[DEBUG] Should trigger rescan: ${submittedRatio >= managerConfigThreshold && (artifact.totalScanners ?? 0) <= 0}`);

    if (submittedRatio >= managerConfigThreshold && (artifact.totalScanners ?? 0) <= 0) {
      console.log(`[INFO] Triggering rescan for artifact ${artifact._id}`);
      
      // Find the phase that contains this artifact
      const phase = await PhaseModel.findOne({ artifacts: artifact._id });
      if (!phase) {
        console.error(`[ERROR] Could not find phase containing artifact ${artifact._id}`);
        return;
      }

      console.log(`[INFO] Found phase ${phase._id} for artifact ${artifact._id}`);

      // Update totalScanners to prevent multiple scans
      await ArtifactModel.findByIdAndUpdate(artifact._id, { 
        $set: { totalScanners: 1 } 
      });

      // Trigger quét lại artifact với phase ID thực
      setImmediate(async () => {
        try {
          console.log(`[INFO] Starting background scan for artifact ${artifact._id}`);
          await scanArtifact(artifact, phase._id.toString());
          console.log(`[SUCCESS] Background scan completed for artifact ${artifact._id}`);
        } catch (error) {
          console.error(`[ERROR] Scanning failed for artifact ${artifact._id}:`, error);
          // Reset totalScanners on failure
          await ArtifactModel.findByIdAndUpdate(artifact._id, { 
            $set: { totalScanners: 0 } 
          });
        }
      });
    } else {
      console.log(`[INFO] Rescan not triggered - ratio: ${submittedRatio.toFixed(2)}%, threshold: ${managerConfigThreshold}%, scanners: ${artifact.totalScanners ?? 0}`);
    }
  }