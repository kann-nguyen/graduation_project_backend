import { Request, Response } from "express";
import { ThirdPartyModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import { safeGithubClient, safeGitlabClient } from "../utils/token";

/**
 * Lấy danh sách tất cả các dịch vụ bên thứ ba đã được lưu trong hệ thống.
 */
export async function getAll(req: Request, res: Response) {
  try {
    const thirdParties = await ThirdPartyModel.find();
    return res.json(successResponse(thirdParties, "Third parties found"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Lấy thông tin chi tiết của một dịch vụ bên thứ ba dựa trên ID.
 */
export async function get(req: Request, res: Response) {
  const { id } = req.params;
  try {
    const thirdParty = await ThirdPartyModel.findById(id);
    return res.json(successResponse(thirdParty, "Third party found"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Tạo mới một dịch vụ bên thứ ba.
 */
export async function create(req: Request, res: Response) {
  const { data } = req.body;
  try {
    const newThirdParty = await ThirdPartyModel.create(data);
    return res.json(successResponse(null, "Third party created"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Cập nhật thông tin của một dịch vụ bên thứ ba dựa trên ID.
 */
export async function update(req: Request, res: Response) {
  const { id } = req.params;
  const { data } = req.body;
  try {
    const updatedThirdParty = await ThirdPartyModel.findByIdAndUpdate(id, data, {
      new: true, // Trả về dữ liệu mới sau khi cập nhật
    });
    return res.json(successResponse(null, "Third party updated"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Xóa một dịch vụ bên thứ ba khỏi hệ thống dựa trên ID.
 */
export async function remove(req: Request, res: Response) {
  const { id } = req.params;
  try {
    const deletedThirdParty = await ThirdPartyModel.findByIdAndDelete(id);
    return res.json(successResponse(null, "Third party deleted"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Lấy danh sách repository từ GitHub của người dùng.
 */
export async function getReposFromGithub(req: Request, res: Response) {
  const account = req.user;
  if (!account) {
    return res.json(errorResponse("You are not authenticated"));
  }
  try {
    // Tìm thông tin tài khoản GitHub được liên kết với user
    const thirdParty = account.thirdParty.find((x) => x.name === "Github");
    if (!thirdParty) {
      return res.json(errorResponse("No Github account linked"));
    }

    const { username } = thirdParty;

    // Tạo GitHub API client an toàn
    const octokit = await safeGithubClient(account._id);

    // Lấy danh sách repository từ GitHub
    const repos = await octokit.rest.repos.listForAuthenticatedUser({
      username,
      type: "owner", // Chỉ lấy repo mà user sở hữu
    });

    // Định dạng dữ liệu trước khi trả về client
    const formattedRepos = repos.data.map((repo) => ({
      name: repo.full_name,
      url: repo.html_url,
      status: repo.visibility || 'unknown',
      owner: repo.owner.login,
    }));

    return res.json(successResponse(formattedRepos, "Github repos found"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Lấy danh sách repository từ GitLab của người dùng.
 */
export async function getReposFromGitlab(req: Request, res: Response) {
  const account = req.user;
  if (!account) {
    return res.json(errorResponse("You are not authenticated"));
  }
  try {
    // Tìm thông tin tài khoản GitLab được liên kết với user
    // const thirdParty = account.thirdParty.find((x) => x.name === "Gitlab");
    // if (!thirdParty) {
    //   return res.json(errorResponse("No Gitlab account linked"));
    // }

    // const { username, accessToken } = thirdParty;
    // if (!accessToken) {
    //   return res.json(errorResponse("No Gitlab access token"));
    // }

    // // Tạo GitLab API client an toàn
    // const api = await safeGitlabClient(account._id);

    // // Lấy danh sách repository từ GitLab
    // const repos = await api.Projects.all({
    //   owned: true, // Chỉ lấy repo mà user sở hữu
    //   orderBy: "name",
    //   sort: "asc",
    // });

    // // Định dạng dữ liệu trước khi trả về client
    // const formattedRepos = repos.map(({ visibility, owner, path_with_namespace, web_url }) => ({
    //   name: path_with_namespace,
    //   url: web_url,
    //   status: visibility,
    //   owner: owner.name,
    // }));

    //return res.json(successResponse(formattedRepos, "Gitlab repos found"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
 