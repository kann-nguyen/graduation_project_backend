import { Request, Response } from "express";
import { ChangeHistoryModel, TicketModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import mongoose from "mongoose";

// Lấy lịch sử thay đổi theo Object ID
export async function getChangeHistoryByObjectId(req: Request, res: Response) {
  const { objectId } = req.params;
  try {
    // Tìm danh sách lịch sử thay đổi theo objectId
    const list = await ChangeHistoryModel.find({
      objectId: new mongoose.Types.ObjectId(objectId),
    });
    
    // Trả về danh sách lịch sử thay đổi nếu tìm thấy
    return res.json(
      successResponse(list, "Change history fetched successfully")
    );
  } catch (error) {
    // Xử lý lỗi nếu có vấn đề trong quá trình lấy dữ liệu
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

// Lấy lịch sử thay đổi của admin, bỏ qua lịch sử liên quan đến Ticket
export async function getAdminChangeHistory(req: Request, res: Response) {
  const { total } = req.query as { total: string };
  try {
    // Tìm {total} lịch sử thay đổi gần nhất, bỏ qua những lịch sử có ObjectId thuộc Ticket
    const list = await ChangeHistoryModel.find(
      {
        description: { $not: /ticket/i },
      },
      null,
      { sort: { timestamp: -1 }, limit: parseInt(total) }
    );
    
    // Trả về danh sách lịch sử thay đổi nếu tìm thấy
    return res.json(
      successResponse(list, "Change history fetched successfully")
    );
  } catch (error) {
    // Xử lý lỗi nếu có vấn đề trong quá trình lấy dữ liệu
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
