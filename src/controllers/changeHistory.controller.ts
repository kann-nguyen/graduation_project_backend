import { Request, Response } from "express";
import { ChangeHistoryModel, TicketModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import mongoose from "mongoose";

export async function getChangeHistoryByObjectId(req: Request, res: Response) {
  const { objectId } = req.params;
  try {
    const list = await ChangeHistoryModel.find({
      objectId: new mongoose.Types.ObjectId(objectId),
    });
    return res.json(
      successResponse(list, "Change history fetched successfully")
    );
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
export async function getAdminChangeHistory(req: Request, res: Response) {
  const { total } = req.query as { total: string };
  try {
    // Find the latest {total} change history except for any ChangeHistory that has ObjectId belongs to the "Ticket" collection
    const list = await ChangeHistoryModel.find(
      {
        description: { $not: /ticket/i },
      },
      null,
      { sort: { timestamp: -1 }, limit: parseInt(total) }
    );
    return res.json(
      successResponse(list, "Change history fetched successfully")
    );
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
