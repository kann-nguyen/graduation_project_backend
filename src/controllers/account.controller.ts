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
import permissions from "../utils/permission"; // Fixed import statement

// Get account details of the authenticated user
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

// Get all accounts from the database
export async function getAll(req: Request, res: Response) {
  try {
    const accounts = await AccountModel.find();
    return res.json(successResponse(accounts, "Accounts found"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

// Get a specific account by ID
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

// Create a new account
export async function create(req: Request, res: Response) {
  try {
    const { username, password, confirmPassword, email, role } = req.body;

    if (password !== confirmPassword) {
      return res.status(400).json(errorResponse("Passwords do not match"));
    }

    // Check if account exists
    const accountExists = await AccountModel.findOne({ username });
    if (accountExists) {
      return res.status(400).json(errorResponse("Username already exists"));
    }

    const emailUsed = await AccountModel.findOne({ email });
    if (emailUsed) {
      return res.status(400).json(errorResponse("Email already used"));
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create account with specified role or default to "member"
    const newAccount = await AccountModel.create({
      username,
      password: hashedPassword,
      email,
      role: role || "member", // Use provided role or default to "member"
    });

    // Create user
    const name = generateRandomName();
    const newUser = await UserModel.create({ account: newAccount._id, name });

    await ChangeHistoryModel.create({
      objectId: newAccount._id,
      action: "create",
      timestamp: Date.now(),
      description: `Account ${newAccount.username} is created with role: ${newAccount.role}`,
      account: newAccount._id,
    });
    return res
      .status(201)
      .json(successResponse(null, "Account created"));
  } catch (error) {
    return res
      .status(500)
      .json(errorResponse(`Internal server error: ${(error as Error).message}`));
  }
}

//change password
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

//update thông tin tài khoản
export async function updateAccountInfo(req: Request, res: Response) {
  const { id } = req.params;
  const { data } = req.body;
  if (!data) return res.json(errorResponse("Missing payload"));

  try {
    // Get current account info to check for role changes
    const currentAccount = await AccountModel.findById(id);
    if (!currentAccount) return res.json(errorResponse("Account not found"));

    // Update account info first
    const account = await AccountModel.findByIdAndUpdate(id, data, {
      new: true,
    });

    // If role is being changed, update permissions accordingly
    if (data.role && data.role !== currentAccount.role) {
      let updatedPermissions;

      // If changed to admin, grant all permissions
      if (data.role === "admin") {
        updatedPermissions = permissions;
      }
      // If changed to project_manager, grant project-related permissions
      else if (data.role === "project_manager") {
        updatedPermissions = permissions.filter((p) => {
          return (
            !p.includes("user") &&
            (p.includes("project") ||
              p.includes("phase") ||
              p.includes("artifact") ||
              p.includes("task"))
          );
        });
      }
      // If changed to security_expert, grant security-related permissions
      else if (data.role === "security_expert") {
        updatedPermissions = permissions.filter((p) => {
          return (
            !p.includes("user") &&
            (p.includes("ticket") ||
              p.includes("threat") ||
              p.includes("vulnerability") ||
              p.includes("mitigation"))
          );
        });
      }
      // If changed to member, grant limited read permissions
      else {
        updatedPermissions = permissions.filter((p) => {
          return (
            !p.includes("user") &&
            !p.includes("project") &&
            !p.includes("artifact") &&
            p.includes("read")
          );
        });
      }

      // Update permissions based on new role
      await AccountModel.findByIdAndUpdate(id, {
        permission: updatedPermissions,
      });
    }

    await ChangeHistoryModel.create({
      objectId: account?._id || null,
      action: "update",
      timestamp: Date.now(),
      description: `Account ${account?.username || "unknown"} is updated${
        data.role ? ` with new role: ${data.role}` : ""
      }`,
      account: req.user?._id,
    });

    return res.json(successResponse(null, "Account info updated"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

//remove tài khoản
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

//thay đổi quyền của user
export async function updateAccountPermission(req: Request, res: Response) {
  const { id } = req.params;
  const { data } = req.body; // data is an array of permitted permission
  if (!data) return res.json(errorResponse("Missing payload"));

  try {
    // First, get the account to check its role
    const accountToUpdate = await AccountModel.findById(id);
    if (!accountToUpdate)
      return res.json(errorResponse("Account not found"));

    // For admin accounts, always give all permissions regardless of what was requested
    const permissionsToSet =
      accountToUpdate.role === "admin"
        ? permissions // Import all permissions from utils/permission
        : data;

    // Update the account with the determined permissions
    const account = await AccountModel.findByIdAndUpdate(id, {
      permission: permissionsToSet,
    });

    await ChangeHistoryModel.create({
      objectId: account?._id || null,
      action: "update",
      timestamp: Date.now(),
      description: `Account ${account?.username || "unknown"} permission is updated`,
      account: req.user?._id,
    });

    return res.json(successResponse(null, "Account permission updated"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

//thay đổi kết nối github
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
    const accountUpdated = await AccountModel.findOneAndUpdate(
      filter,
      update,
      {
        new: true,
      }
    );
    await ChangeHistoryModel.create({
      objectId: account._id,
      action: "update",
      timestamp: Date.now(),
      description: `Account ${account.username} Github token is updated`,
      account: req.user?._id,
    });
    return res.json(
      successResponse(null, "Github access token updated")
    );
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

//thay đổi kết nối gitlab
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
    const accountUpdated = await AccountModel.findOneAndUpdate(
      filter,
      update,
      {
        new: true,
      }
    );
    await ChangeHistoryModel.create({
      objectId: account._id,
      action: "update",
      timestamp: Date.now(),
      description: `Account ${account.username} Gitlab token is updated`,
      account: req.user?._id,
    });
    return res.json(
      successResponse(null, "Gitlab access token updated")
    );
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

//xóa kết nối github
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

//xóa kết nối gitlab
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

//thay đổi scanner của 1 tài khoản
export async function updateScannerPreference(req: Request, res: Response) {
  const id = req.user?._id; // Lấy ID của tài khoản từ request (nếu có)
  const { data } = req.body; // Lấy dữ liệu từ request body
  const { scanner: scannerName, endpoint } = data; // Trích xuất thông tin máy quét từ dữ liệu nhận được

  try {
    // Tìm máy quét trong database dựa vào tên scannerName
    const scanner = await ScannerModel.findOne({ name: scannerName });

    // Cập nhật thông tin máy quét cho tài khoản
    const acc = await AccountModel.findByIdAndUpdate(id, {
      scanner: {
        endpoint, // Cập nhật endpoint mới của máy quét
        details: scanner, // Gán thông tin chi tiết về máy quét từ database
      },
    });

    // Ghi lại lịch sử thay đổi vào bảng ChangeHistoryModel
    await ChangeHistoryModel.create({
      objectId: acc?._id, // ID của tài khoản vừa cập nhật
      action: "update", // Hành động là "update"
      timestamp: Date.now(), // Ghi lại thời gian cập nhật
      description: `Account ${acc?.username} scanner preference is updated`, // Mô tả thay đổi
      account: req.user?._id, // Người thực hiện thay đổi
    });

    // Trả về phản hồi thành công
    return res.json(successResponse(null, "Scanner preference updated"));
  } catch (error) {
    // Trả về lỗi nếu có vấn đề trong quá trình xử lý
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
