import { Ref } from "@typegoose/typegoose";
import { Request, Response } from "express";
import {
  AccountModel,
  ActivityHistoryModel,
  ProjectModel,
  UserModel,
} from "../models/models";
import { Project } from "../models/project";
import MyOctokit from "../octokit";
import redis from "../redis";
import { errorResponse, successResponse } from "../utils/responseFormat";
import { GitlabType, OctokitType } from "..";
import { Gitlab } from "@gitbeaker/rest";
import { safeGithubClient, safeGitlabClient } from "../utils/token";
import { Types } from "mongoose";

// Hàm lấy danh sách Merge Requests (Pull Requests) từ GitLab
async function getPullRequestsGitlab(
  api: GitlabType, // Đối tượng API GitLab
  projectName: string, // Tên dự án trên GitLab
  projectId: Ref<Project> // ID của dự án trong hệ thống
) {
  try {
    // Gọi API để lấy danh sách Merge Requests (MRs)
    const prData = await api.MergeRequests.all({
      projectId: projectName, // Dùng projectName để lấy danh sách MR
    });

    // Xử lý dữ liệu nhận được từ GitLab
    const processedPrData = prData.map(
      ({ id, title: content, created_at, author }) => {
        const createdAt = created_at as string; // Ngày tạo MR
        const createdBy = author?.username as string; // Tên người tạo MR
        return {
          id, // ID của MR
          action: "pr", // Gắn nhãn hành động là "pr"
          content, // Tiêu đề của MR
          createdAt, // Thời gian tạo
          createdBy, // Người tạo
          projectId, // ID của dự án
        };
      }
    );
    return processedPrData; // Trả về danh sách MR đã xử lý
  } catch (error) {
    console.log(error); // Ghi log nếu có lỗi
    return []; // Trả về mảng rỗng nếu có lỗi
  }
}

// Hàm fetch dữ liệu mới nhất từ GitLab
async function fetchLatestFromGitlab(
  projectName: string, // Tên dự án trên GitLab
  accountId: Types.ObjectId | undefined, // ID tài khoản của người dùng
  projectId: Ref<Project> // ID của dự án trong hệ thống
) {
  if (!projectName) {
    return new Error("Missing encodedUrl"); // Trả về lỗi nếu không có tên dự án
  }

  // Kiểm tra cache trong Redis để tránh gọi API quá nhiều lần
  const cache = await redis.get(`gitlab-${projectName}`);
  if (cache) return; // Nếu đã có cache, không cần fetch lại dữ liệu

  // Lấy API client an toàn dựa trên tài khoản
  const api = await safeGitlabClient(accountId);

  // Lưu thời gian fetch vào cache Redis (hết hạn sau 60 giây)
  redis.set(`gitlab-${projectName}`, Date.now().toString(), "EX", 60);

  // Lấy danh sách commits từ GitLab
  const processedCommitData = await getCommitsGitlab(api, projectName, projectId);
  
  // Lấy danh sách Merge Requests từ GitLab
  const processedPrData = await getPullRequestsGitlab(api, projectName, projectId);

  // Nếu không có dữ liệu, trả về lỗi
  if (!processedPrData || !processedCommitData) {
    return new Error("Error fetching data from Gitlab");
  }

  try {
    // Lưu dữ liệu vào database
    await insertDataToDatabase(
      processedPrData,
      processedCommitData,
      projectId,
      "Gitlab"
    );
    return;
  } catch (error) {
    return; // Nếu lỗi khi lưu dữ liệu, bỏ qua và không trả về lỗi
  }
}

// Hàm lấy danh sách commits từ GitLab
async function getCommitsGitlab(
  api: GitlabType, // Đối tượng API GitLab
  projectName: string, // Tên dự án trên GitLab
  projectId: Ref<Project> // ID của dự án trong hệ thống
) {
  try {
    // Gọi API để lấy danh sách commits
    const commits = await api.Commits.all(projectName);

    // Xử lý dữ liệu commit từ GitLab
    const processedCommitData = commits.map(
      ({ id, title: content, created_at, author_name }) => {
        const createdAt = created_at as string; // Ngày tạo commit
        const createdBy = author_name as string; // Tên người tạo commit
        return {
          id, // ID commit
          action: "commit", // Gắn nhãn hành động là "commit"
          content, // Nội dung commit (message)
          createdAt, // Thời gian tạo commit
          createdBy, // Người tạo commit
          projectId, // ID dự án
        };
      }
    );
    return processedCommitData; // Trả về danh sách commits đã xử lý
  } catch (error) {
    console.log(error); // Ghi log lỗi nếu có
    return []; // Trả về mảng rỗng nếu có lỗi
  }
}

// Hàm lấy danh sách Pull Requests từ GitHub
async function getPullRequestsGithub(
  octokit: OctokitType, // Đối tượng API của GitHub
  owner: string, // Chủ sở hữu repository (user hoặc org)
  repo: string, // Tên repository
  projectId: Ref<Project> // ID của dự án trong hệ thống
) {
  try {
    const prData = [];

    // Sử dụng octokit để lấy tất cả Pull Requests của repository theo từng trang
    for await (const response of octokit.paginate.iterator(
      octokit.rest.pulls.list,
      {
        owner,
        repo,
        per_page: 100, // Giới hạn 100 PRs mỗi trang
        state: "all", // Lấy tất cả trạng thái (open, closed, merged)
      }
    )) {
      prData.push(response.data);
    }

    // Chuyển đổi dữ liệu PR thành định dạng phù hợp
    const processedPrData = prData
      .flat()
      .map(({ id, title: content, created_at: createdAt, user }) => {
        const createdBy = user?.login; // Lấy username của người tạo PR
        return {
          id, // ID của PR
          action: "pr", // Gắn nhãn hành động là "pr"
          content, // Tiêu đề PR
          createdAt, // Ngày tạo PR
          createdBy, // Người tạo PR
          projectId, // ID dự án
        };
      });

    return processedPrData; // Trả về danh sách PR đã xử lý
  } catch (error) {
    return []; // Trả về mảng rỗng nếu có lỗi
  }
}

// Hàm lấy danh sách commits từ GitHub
async function getCommitsGithub(
  octokit: OctokitType, // Đối tượng API GitHub
  owner: string, // Chủ sở hữu repository
  repo: string, // Tên repository
  projectId: Ref<Project> // ID của dự án trong hệ thống
) {
  try {
    const commits = [];

    // Sử dụng octokit để lấy danh sách commits của repository theo từng trang
    for await (const response of octokit.paginate.iterator(
      octokit.rest.repos.listCommits,
      {
        owner,
        repo,
        per_page: 100, // Giới hạn 100 commits mỗi trang
      }
    )) {
      commits.push(response.data);
    }

    // Xử lý dữ liệu commits nhận được từ GitHub
    const processedCommitData = commits.flat().map(({ sha: id, commit }) => {
      const content = commit.message; // Nội dung commit (message)
      const createdBy = commit.author?.name; // Tên người tạo commit
      const createdAt = commit.author?.date; // Ngày tạo commit
      return {
        id, // ID commit (SHA hash)
        action: "commit", // Gắn nhãn hành động là "commit"
        content, // Nội dung commit
        createdAt, // Thời gian tạo commit
        createdBy, // Người tạo commit
        projectId, // ID dự án
      };
    });

    return processedCommitData; // Trả về danh sách commits đã xử lý
  } catch (error) {
    console.error(`[getCommitsGithub] Error:`, error);// Ghi log lỗi nếu có
    return []; // Trả về mảng rỗng nếu có lỗi
  }
}

// Hàm fetch dữ liệu mới nhất từ GitHub
async function fetchLatestFromGithub(
  owner: string | undefined, // Chủ sở hữu repository
  repo: string | undefined, // Tên repository
  accountId: Types.ObjectId | undefined, // ID tài khoản của người dùng
  projectId: Ref<Project> // ID của dự án trong hệ thống
) {
  if (!owner || !repo) {
    return new Error("Missing owner, repo"); // Trả về lỗi nếu thiếu thông tin repo
  }

  // Kiểm tra cache trong Redis để tránh gọi API quá nhiều lần
  const cache = await redis.get(`github-${repo}`);
  if (cache) {
    return; // Nếu đã có cache, không cần fetch lại dữ liệu
  } 

  // Lấy API client an toàn dựa trên tài khoản
  const octokit = await safeGithubClient(accountId);

  // Lưu thời gian fetch vào cache Redis (hết hạn sau 60 giây)
  redis.set(`github-${repo}`, Date.now().toString(), "EX", 60);

  // Lấy danh sách Pull Requests từ GitHub
  const processedPrData = await getPullRequestsGithub(
    octokit,
    owner,
    repo,
    projectId
  );

  // Lấy danh sách commits từ GitHub
  const processedCommitData = await getCommitsGithub(
    octokit,
    owner,
    repo,
    projectId
  );

  // Nếu không có dữ liệu, trả về lỗi
  if (!processedPrData || !processedCommitData) {
    console.error(`[fetchLatestFromGithub] No data retrieved`);
    return new Error("Error fetching data from Github");
  }

  try {
    // Lưu dữ liệu vào database
    await insertDataToDatabase(
      processedPrData,
      processedCommitData,
      projectId,
      "Github"
    );
    return;
  } catch (error) {
    return; // Nếu lỗi khi lưu dữ liệu, bỏ qua và không trả về lỗi
  }
}

// API lấy lịch sử hoạt động của project từ GitHub hoặc GitLab
export async function getActivityHistory(req: Request, res: Response) {
  const { projectName } = req.params; // Lấy projectName từ request params
  const { username } = req.query; // Lấy username từ query (nếu có)

  try {
    // Tìm user dựa trên username (nếu có)
    const user = await AccountModel.findOne({ username });

    // Tìm project theo tên
    const project = await ProjectModel.findOne({ name: projectName });
    if (!project) {
      return res.json(errorResponse("Project not found")); // Nếu không tìm thấy project, trả về lỗi
    }

    const { url, _id } = project; // Lấy URL repo và ID của project

    // Kiểm tra nếu project là repo GitHub
    if (url.includes("github")) {
      const [owner, repo] = projectName.split("/"); // Tách owner và repo từ tên project
      const result = await fetchLatestFromGithub(owner, repo, req.user?._id, _id);

      // Nếu có lỗi khi fetch dữ liệu, trả về lỗi
      if (result instanceof Error) {
        return res.json(errorResponse(`Error updating latest activity history: ${result.message}`));
      }

      // Nếu có username, tìm lịch sử hoạt động của user trong project
      if (user) {
        const actHist = await ActivityHistoryModel.find({
          projectId: _id,
          createdBy: user.thirdParty.find((x) => x.name === "Github")?.username,
        });

        return res.json(successResponse(actHist, "Successfully retrieved activity history"));
      }

      // Nếu không có username, lấy toàn bộ lịch sử hoạt động của project
      const actHist = await ActivityHistoryModel.find({ projectId: _id });
      return res.json(successResponse(actHist, "Successfully retrieved activity history"));
    }

    // Kiểm tra nếu project là repo GitLab
    else if (url.includes("gitlab")) {
      const result = await fetchLatestFromGitlab(projectName, req.user?._id, _id);

      // Nếu có lỗi khi fetch dữ liệu, trả về lỗi
      if (result instanceof Error) {
        return res.json(errorResponse(`Error updating latest activity history: ${result.message}`));
      }

      // Nếu có username, tìm lịch sử hoạt động của user trong project
      if (user) {
        const actHist = await ActivityHistoryModel.find({
          projectId: _id,
          createdBy: user.thirdParty.find((x) => x.name === "Gitlab")?.username,
        });
        return res.json(successResponse(actHist, "Successfully retrieved activity history"));
      }

      // Nếu không có username, lấy toàn bộ lịch sử hoạt động của project
      const actHist = await ActivityHistoryModel.find({ projectId: _id });
      return res.json(successResponse(actHist, "Successfully retrieved activity history"));
    }
  } catch (error) {
    console.error(`[getActivityHistory] Internal server error:`, error);
    return res.json(errorResponse(`Internal server error: ${error}`)); // Trả về lỗi nếu có vấn đề trong quá trình xử lý
  }
}

// API lấy lịch sử hoạt động của user trong một project cụ thể
export async function getActivityHistoryByUsername(req: Request, res: Response) {
  const { username, projectName } = req.params; // Lấy username và projectName từ request params

  try {
    // Tìm project theo tên
    const project = await ProjectModel.findOne({ name: projectName });
    if (!project) {
      return res.json(errorResponse("No project found")); // Nếu không tìm thấy project, trả về lỗi
    }

    // Tìm user theo username
    const user = await AccountModel.findOne({ username });
    if (!user) {
      return res.json(errorResponse("No user found")); // Nếu không tìm thấy user, trả về lỗi
    }

    // Tìm lịch sử hoạt động của user trong project
    const actHist = await ActivityHistoryModel.find({
      createdBy: user.thirdParty.find((x) => x.name === "Github")?.username,
      projectId: project._id,
    });

    return res.json(successResponse(actHist, "Successfully retrieved activity history"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`)); // Trả về lỗi nếu có vấn đề trong quá trình xử lý
  }
}


async function insertDataToDatabase(
  processedPrData: {
    id: number;
    action: string;
    content: string;
    createdAt: string;
    createdBy: string | undefined;
    projectId: Ref<Project>;
  }[],
  processedCommitData: {
    id: string;
    action: string;
    content: string;
    createdAt: string | undefined;
    createdBy: string | undefined;
    projectId: Ref<Project>;
  }[],
  projectId: Ref<Project>,
  party: "Gitlab" | "Github"
) {
  // To be safe, delete all history for this project first
  await ActivityHistoryModel.deleteMany({ projectId });
  await ActivityHistoryModel.insertMany(
    [...processedPrData, ...processedCommitData],
    {
      ordered: false,
    }
  );
  // Add history to each user in the project
  const history = await ActivityHistoryModel.find({ projectId });
  const users = await UserModel.find({ projectIn: projectId });
  users.forEach(async (user) => {
    // Clear each user's history
    await UserModel.updateMany(
      { _id: user._id },
      {
        $set: {
          activityHistory: [],
        },
      }
    );
    const account = await AccountModel.findById(user.account);
    if (!account) {
      return;
    }
    const thirdPartyUsername = account.thirdParty.find(
      (x) => x.name === party
    )?.username;
    const userHistory = history.filter(
      ({ createdBy }) => createdBy === thirdPartyUsername
    );
    await UserModel.findByIdAndUpdate(
      user._id,
      { $addToSet: { activityHistory: userHistory } },
      { new: true }
    );
  });
}
