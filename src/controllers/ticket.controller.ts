import { Request, Response } from "express";
import { ChangeHistoryModel, TicketModel, UserModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";

export async function getAll(req: Request, res: Response) {
  const { projectName } = req.query;
  if (!projectName) {
    return res.json(errorResponse("Project name is required"));
  }
  try {
    const tickets = await TicketModel.find({
      projectName,
    }).populate({
      path: "assignee assigner",
    });
    return res.json(successResponse(tickets, "Tickets fetched successfully"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

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

export async function create(req: Request, res: Response) {
  const { data } = req.body;
  // data.assignee is UserModel _id
  try {
    const assigner = await UserModel.findOne({ account: req.user?._id });
    const assignee = await UserModel.findById(data.assignee);
    const ticket = await TicketModel.create({
      ...data,
      assignee: assignee?._id,
      assigner: assigner?._id,
    });
    await UserModel.findByIdAndUpdate(data.assignee, {
      $push: {
        ticketAssigned: ticket._id,
      },
    });
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

export async function update(req: Request, res: Response) {
  const { id } = req.params;
  const { data } = req.body;
  try {
    const ticket = await TicketModel.findByIdAndUpdate(id, data, { new: true });
    if (ticket) {
      // Temporarily, this function is only used for ticket status update
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
