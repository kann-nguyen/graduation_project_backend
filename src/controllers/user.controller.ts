import { Request, Response } from "express";
import { AccountModel, UserModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
export async function get(req: Request, res: Response) {
  // Allows to get a user by memberId or accountId
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

export async function create(req: Request, res: Response) {
  try {
    const user = await UserModel.create(req.body);
    return res.json(successResponse(null, "User created"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function update(req: Request, res: Response) {
  const account = req.user;
  const { name, email } = req.body;
  if (!account) return res.json(errorResponse("You are not authenticated"));
  try {
    const accountUpdate = await AccountModel.findByIdAndUpdate(account._id, {
      email,
    });
    const userUpdate = await UserModel.findOneAndUpdate(
      { account: account._id },
      { name }
    );
    return res.json(successResponse(null, "Info updated"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function remove(req: Request, res: Response) {
  const { id } = req.params;
  try {
    const user = await UserModel.findByIdAndDelete(id);
    return res.json(successResponse(null, "User deleted"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function assignTask(req: Request, res: Response) {
  const { id, taskId } = req.params;
  try {
    // Check if task has already been assigned
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

export async function addProjectIn(req: Request, res: Response) {
  const { id } = req.params;
  const { projectId } = req.body;
  try {
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

export async function getProjectIn(req: Request, res: Response) {
  const account = req.user;
  if (!account) return res.json(errorResponse("Not logged in"));
  const id = account._id;
  try {
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

export async function getAllUsers(req: Request, res: Response) {
  try {
    const users = await UserModel.find().populate({
      path: "account",
    });
    return res.json(successResponse(users, "List of users fetched"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
