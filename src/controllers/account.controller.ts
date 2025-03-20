import bcrypt from "bcrypt";
import "dotenv/config";
import { Request, Response } from "express";
import {
  AccountModel,
  ChangeHistoryModel,
  ScannerModel,
  ThirdPartyModel,
  UserModel,
} from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import generateRandomName from "../utils/generateName";

export async function get(req: Request, res: Response) {
  try {
    const account = req.user;
    if (!account) {
      return res.json(errorResponse("Unauthenticated"));
    }
    const findedAccount = await AccountModel.findById(account._id, {
      password: 0,
    });
    if (!findedAccount) {
      return res.json(errorResponse("No account is found in the database"));
    }
    return res.json(successResponse(findedAccount, "Account found"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function getAll(req: Request, res: Response) {
  try {
    const accounts = await AccountModel.find();
    return res.json(successResponse(accounts, "Accounts found"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function getById(req: Request, res: Response) {
  const { id } = req.params;
  try {
    const account = await AccountModel.findById(id);
    if (!account) {
      return res.json(
        errorResponse(`No account with ${id} is found in the database`)
      );
    }
    return res.json(successResponse(account, "Account found"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function create(req: Request, res: Response) {
  const { username, password, confirmPassword, email } = req.body;
  if (password !== confirmPassword) {
    return res.json(errorResponse("Passwords do not match"));
  }
  // Check if account exists
  const accountExists = await AccountModel.findOne({ username });
  if (accountExists) {
    return res.json(errorResponse("Username already exists"));
  }
  const emailUsed = await AccountModel.findOne({ email });
  if (emailUsed) {
    return res.json(errorResponse("Email already used"));
  }
  // Hash password
  const hashedPassword = await bcrypt.hash(password, 10);
  // Create account
  try {
    const newAccount = await AccountModel.create({
      username,
      password: hashedPassword,
      email,
    });
    // Create user
    const name = generateRandomName();
    await UserModel.create({ account: newAccount._id, name });
    await ChangeHistoryModel.create({
      objectId: newAccount._id,
      action: "create",
      timestamp: Date.now(),
      description: `Account ${newAccount.username} is created`,
      account: newAccount._id,
    });
    return res.json(successResponse(null, "Account created"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function changePassword(req: Request, res: Response) {
  const id = req.user?._id;
  const { data } = req.body;
  const { oldPassword, newPassword } = data;
  if (!oldPassword || !newPassword) {
    return res.json(errorResponse("Missing old or new password"));
  }
  try {
    // Check if account exists
    const account = await AccountModel.findById(id);
    if (!account) {
      return res.json(errorResponse("Account not found"));
    }
    // Check if old password is correct
    const isMatch = await bcrypt.compare(oldPassword, account.password);
    if (!isMatch) {
      return res.json(errorResponse("Incorrect old password"));
    }
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    // Change password
    await AccountModel.findByIdAndUpdate(id, { password: hashedPassword });
    return res.json(successResponse(null, "Password changed"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function updateAccountInfo(req: Request, res: Response) {
  const { id } = req.params;
  const { data } = req.body;
  if (!data) return res.json(errorResponse("Missing payload"));
  // Update account info
  try {
    const account = await AccountModel.findByIdAndUpdate(id, data, {
      new: true,
    });
    if (!account) return res.json(errorResponse("Account not found"));
    await ChangeHistoryModel.create({
      objectId: account._id,
      action: "update",
      timestamp: Date.now(),
      description: `Account ${account.username} is updated`,
      account: req.user?._id,
    });
    return res.json(successResponse(null, "Account info updated"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function remove(req: Request, res: Response) {
  const { id } = req.params;
  try {
    const account = await AccountModel.findByIdAndDelete(id);
    if (!account) {
      return res.json(errorResponse("Account not found"));
    }
    return res.json(successResponse(null, "Account deleted"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function updateAccountPermission(req: Request, res: Response) {
  const { id } = req.params;
  const { data } = req.body; // data is an array of permitted permission
  if (!data) return res.json(errorResponse("Missing payload"));
  try {
    const account = await AccountModel.findByIdAndUpdate(id, {
      permission: data,
    });
    if (!account) return res.json(errorResponse("Account not found"));
    await ChangeHistoryModel.create({
      objectId: account._id,
      action: "update",
      timestamp: Date.now(),
      description: `Account ${account.username} permission is updated`,
      account: req.user?._id,
    });
    return res.json(successResponse(null, "Account permission updated"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
export async function updateGithubAccessToken(req: Request, res: Response) {
  const id = req.user?._id;
  const { data } = req.body;
  try {
    const account = await AccountModel.findById(id);
    if (!account) return res.json(errorResponse("Account not found"));
    // Find the third party in the account that has the name of "Github" and then update the access token
    const filter = {
      _id: id,
      "thirdParty.name": "Github",
    };
    const update = {
      $set: {
        "thirdParty.$.accessToken": data,
      },
    };
    const accountUpdated = await AccountModel.findOneAndUpdate(filter, update, {
      new: true,
    });
    await ChangeHistoryModel.create({
      objectId: account._id,
      action: "update",
      timestamp: Date.now(),
      description: `Account ${account.username} Github token is updated`,
      account: req.user?._id,
    });
    return res.json(successResponse(null, "Github access token updated"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
export async function updateGitlabAccessToken(req: Request, res: Response) {
  const id = req.user?._id;
  const { data } = req.body;
  try {
    const account = await AccountModel.findById(id);
    if (!account) return res.json(errorResponse("Account not found"));
    // Find the third party in the account that has the name of "Github" and then update the access token
    const filter = {
      _id: id,
      "thirdParty.name": "Gitlab",
    };
    const update = {
      $set: {
        "thirdParty.$.accessToken": data,
      },
    };
    const accountUpdated = await AccountModel.findOneAndUpdate(filter, update, {
      new: true,
    });
    await ChangeHistoryModel.create({
      objectId: account._id,
      action: "update",
      timestamp: Date.now(),
      description: `Account ${account.username} Gitlab token is updated`,
      account: req.user?._id,
    });
    return res.json(successResponse(null, "Gitlab access token updated"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
export async function disconnectFromGithub(req: Request, res: Response) {
  const account = req.user;
  try {
    const acc = await AccountModel.findByIdAndUpdate(account?._id, {
      $pull: {
        thirdParty: {
          name: "Github",
        },
      },
    });
    await ChangeHistoryModel.create({
      objectId: acc?._id,
      action: "update",
      timestamp: Date.now(),
      description: `Account ${acc?.username} disconnects from Github`,
      account: req.user?._id,
    });
    return res.json(successResponse(null, "Github disconnected"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
export async function disconnectFromGitlab(req: Request, res: Response) {
  const account = req.user;
  try {
    const acc = await AccountModel.findByIdAndUpdate(account?._id, {
      $pull: {
        thirdParty: {
          name: "Gitlab",
        },
      },
    });
    await ChangeHistoryModel.create({
      objectId: acc?._id,
      action: "update",
      timestamp: Date.now(),
      description: `Account ${acc?.username} disconnects from Gitlab`,
      account: req.user?._id,
    });
    return res.json(successResponse(null, "Gitlab disconnected"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
export async function updateScannerPreference(req: Request, res: Response) {
  const id = req.user?._id;
  const { data } = req.body;
  const { scanner: scannerName, endpoint } = data;
  try {
    const scanner = await ScannerModel.findOne({ name: scannerName });
    const acc = await AccountModel.findByIdAndUpdate(id, {
      scanner: {
        endpoint,
        details: scanner,
      },
    });
    await ChangeHistoryModel.create({
      objectId: acc?._id,
      action: "update",
      timestamp: Date.now(),
      description: `Account ${acc?.username} scanner preference is updated`,
      account: req.user?._id,
    });
    return res.json(successResponse(null, "Scanner preference updated"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
