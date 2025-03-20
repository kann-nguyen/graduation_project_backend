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
async function getPullRequestsGitlab(
  api: GitlabType,
  projectName: string,
  projectId: Ref<Project>
) {
  try {
    const prData = await api.MergeRequests.all({
      projectId: projectName,
    });
    const processedPrData = prData.map(
      ({ id, title: content, created_at, author }) => {
        const createdAt = created_at as string;
        const createdBy = author?.username as string;
        return {
          id,
          action: "pr",
          content,
          createdAt,
          createdBy,
          projectId,
        };
      }
    );
    return processedPrData;
  } catch (error) {
    console.log(error);
    return [];
  }
}
async function getPullRequestsGithub(
  octokit: OctokitType,
  owner: string,
  repo: string,
  projectId: Ref<Project>
) {
  try {
    const prData = [];
    for await (const response of octokit.paginate.iterator(
      octokit.rest.pulls.list,
      {
        owner,
        repo,
        per_page: 100,
        state: "all",
      }
    )) {
      prData.push(response.data);
    }
    const processedPrData = prData
      .flat()
      .map(({ id, title: content, created_at: createdAt, user }) => {
        const createdBy = user?.login;
        return {
          id,
          action: "pr",
          content,
          createdAt,
          createdBy,
          projectId,
        };
      });
    return processedPrData;
  } catch (error) {
    console.log(error);
    return [];
  }
}
async function getCommitsGithub(
  octokit: OctokitType,
  owner: string,
  repo: string,
  projectId: Ref<Project>
) {
  try {
    const commits = [];
    for await (const response of octokit.paginate.iterator(
      octokit.rest.repos.listCommits,
      {
        owner,
        repo,
        per_page: 100,
      }
    )) {
      commits.push(response.data);
    }
    const processedCommitData = commits.flat().map(({ sha: id, commit }) => {
      const content = commit.message;
      const createdBy = commit.author?.name;
      const createdAt = commit.author?.date;
      return {
        id,
        action: "commit",
        content,
        createdAt,
        createdBy,
        projectId,
      };
    });
    return processedCommitData;
  } catch (error) {
    console.log(error);
    return [];
  }
}
async function getCommitsGitlab(
  api: GitlabType,
  projectName: string,
  projectId: Ref<Project>
) {
  try {
    const commits = await api.Commits.all(projectName);
    const processedCommitData = commits.map(
      ({ id, title: content, created_at, author_name }) => {
        const createdAt = created_at as string;
        const createdBy = author_name as string;
        return {
          id,
          action: "commit",
          content,
          createdAt,
          createdBy,
          projectId,
        };
      }
    );
    return processedCommitData;
  } catch (error) {
    console.log(error);
    return [];
  }
}
async function fetchLatestFromGithub(
  owner: string | undefined,
  repo: string | undefined,
  accountId: Types.ObjectId | undefined,
  projectId: Ref<Project>
) {
  if (!owner || !repo) {
    return new Error("Missing owner, repo");
  }
  const cache = await redis.get(`github-${repo}`);
  if (cache) return;
  const octokit = await safeGithubClient(accountId);
  redis.set(`github-${repo}`, Date.now().toString(), "EX", 60);
  const processedPrData = await getPullRequestsGithub(
    octokit,
    owner,
    repo,
    projectId
  );
  const processedCommitData = await getCommitsGithub(
    octokit,
    owner,
    repo,
    projectId
  );
  if (!processedPrData || !processedCommitData) {
    return new Error("Error fetching data from Github");
  }
  try {
    await insertDataToDatabase(
      processedPrData,
      processedCommitData,
      projectId,
      "Github"
    );
    return;
  } catch (error) {
    return;
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
async function fetchLatestFromGitlab(
  projectName: string,
  accountId: Types.ObjectId | undefined,
  projectId: Ref<Project>
) {
  if (!projectName) {
    return new Error("Missing encodedUrl");
  }
  const cache = await redis.get(`gitlab-${projectName}`);
  if (cache) return;
  const api = await safeGitlabClient(accountId);
  redis.set(`gitlab-${projectName}`, Date.now().toString(), "EX", 60);
  const processedCommitData = await getCommitsGitlab(
    api,
    projectName,
    projectId
  );
  const processedPrData = await getPullRequestsGitlab(
    api,
    projectName,
    projectId
  );
  if (!processedPrData || !processedCommitData) {
    return new Error("Error fetching data from Gitlab");
  }
  try {
    await insertDataToDatabase(
      processedPrData,
      processedCommitData,
      projectId,
      "Gitlab"
    );
    return;
  } catch (error) {
    return;
  }
}
export async function getActivityHistory(req: Request, res: Response) {
  const { projectName } = req.params;
  const { username } = req.query;
  try {
    const user = await AccountModel.findOne({ username });
    const project = await ProjectModel.findOne({ name: projectName });
    if (!project) {
      return res.json(errorResponse("Project not found"));
    }
    const { url, _id } = project;
    if (url.includes("github")) {
      const [owner, repo] = projectName.split("/");
      const result = await fetchLatestFromGithub(
        owner,
        repo,
        req.user?._id,
        _id
      );
      if (result instanceof Error) {
        return res.json(
          errorResponse(
            `Error updating latest activity history: ${result.message}`
          )
        );
      }
      // Query by username
      if (user) {
        const actHist = await ActivityHistoryModel.find({
          projectId: _id,
          createdBy: user.thirdParty.find((x) => x.name === "Github")?.username,
        });
        return res.json(
          successResponse(actHist, "Successfully retrieved activity history")
        );
      }
      // Query all
      const actHist = await ActivityHistoryModel.find({
        projectId: _id,
      });
      return res.json(
        successResponse(actHist, "Successfully retrieved activity history")
      );
    } else if (url.includes("gitlab")) {
      const result = await fetchLatestFromGitlab(
        projectName,
        req.user?._id,
        _id
      );
      if (result instanceof Error) {
        return res.json(
          errorResponse(
            `Error updating latest activity history: ${result.message}`
          )
        );
      }
      // Query by username
      if (user) {
        const actHist = await ActivityHistoryModel.find({
          projectId: _id,
          createdBy: user.thirdParty.find((x) => x.name === "Gitlab")?.username,
        });
        return res.json(
          successResponse(actHist, "Successfully retrieved activity history")
        );
      }
      // Query all
      const actHist = await ActivityHistoryModel.find({
        projectId: _id,
      });
      return res.json(
        successResponse(actHist, "Successfully retrieved activity history")
      );
    }
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function getActivityHistoryByUsername(
  req: Request,
  res: Response
) {
  const { username, projectName } = req.params;
  try {
    const project = await ProjectModel.findOne({ name: projectName });
    if (!project) {
      return res.json(errorResponse("No project found"));
    }
    const user = await AccountModel.findOne({ username });
    if (!user) {
      return res.json(errorResponse("No user found"));
    }
    const actHist = await ActivityHistoryModel.find({
      createdBy: user.thirdParty.find((x) => x.name === "Github")?.username,
      projectId: project._id,
    });
    return res.json(
      successResponse(actHist, "Successfully retrieved activity history")
    );
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
