import { Request, Response } from "express";
import MyOctokit from "../octokit";
import { errorResponse, successResponse } from "../utils/responseFormat";
import { Gitlab } from "@gitbeaker/rest";
import { ProjectModel } from "../models/models";
import { GitlabType, OctokitType } from "..";
import { safeGithubClient, safeGitlabClient } from "../utils/token";
export async function getWorkflows(req: Request, res: Response) {
  const { projectName } = req.query as { projectName: string };
  const project = await ProjectModel.findOne({ name: projectName });
  if (!project) {
    return res.json(errorResponse("Project not found"));
  }
  const { url } = project;
  const [owner, repo] = projectName.split("/");
  if (url.includes("github")) {
    const accessToken = req.user?.thirdParty.find(
      (x) => x.name === "Github"
    )?.accessToken;
    const octokit = new MyOctokit({
      auth: accessToken,
    });
    try {
      let workflows = await getGithubWorkflows(octokit, owner, repo);
      return res.json(
        successResponse(workflows, "Successfully fetched workflows")
      );
    } catch (error) {
      return res.json(errorResponse("Failed to fetch workflows"));
    }
  } else if (url.includes("gitlab")) {
    const api = await safeGitlabClient(req.user?._id);
    try {
      let workflows = await getGitlabWorkflows(api, projectName);
      return res.json(
        successResponse(workflows, "Successfully fetched workflows")
      );
    } catch (error) {
      console.log(error);
      return res.json(errorResponse("Failed to fetch workflows"));
    }
  }
}

async function getGithubWorkflows(
  octokit: OctokitType,
  owner: string,
  repo: string
) {
  const { data } = await octokit.rest.actions.listRepoWorkflows({
    owner,
    repo,
  });
  let workflows = [];
  for (const workflow of data.workflows) {
    if (workflow.path.endsWith(".yml")) {
      const { data } = await octokit.rest.repos.getContent({
        owner,
        repo,
        path: workflow.path,
      });
      const fileName = workflow.path.split("/").pop();
      workflows.push({
        name: fileName,
        path: workflow.path,
        // @ts-ignore
        content: Buffer.from(data.content, "base64").toString("utf-8"),
      });
    }
  }
  return workflows;
}

// Only support gitlab-ci.yml for now
async function getGitlabWorkflows(api: GitlabType, projectName: string) {
  // Create an URL encoded path for the project to use for requests
  const projectData = await api.Projects.show(projectName);
  const defaultBranch = projectData.defaultBranch;
  const data = await api.RepositoryFiles.showRaw(
    projectName,
    ".gitlab-ci.yml",
    defaultBranch as string
  );
  return [
    {
      name: ".gitlab-ci.yml",
      path: ".gitlab-ci.yml",
      content: data,
    },
  ];
}

export async function pushNewWorkflow(req: Request, res: Response) {
  const { projectName, branch, data, message } = req.body;
  const project = await ProjectModel.findOne({ name: projectName });
  if (!project) {
    return res.json(errorResponse("Project not found"));
  }
  const { url } = project;
  const [owner, repo] = projectName.split("/");
  if (url.includes("github")) {
    const octokit = await safeGithubClient(req.user?._id);
    try {
      const { data: repoData } = await octokit.rest.repos.get({
        owner,
        repo,
      });
      const defaultBranch = repoData.default_branch;
      const targetBranch = branch || defaultBranch;
      const branchExists = await checkBranchExistsGithub(
        octokit,
        owner,
        repo,
        targetBranch
      );
      if (!branchExists) {
        // Create the branch if it doesn't exist
        await createBranchGithub(
          octokit,
          owner,
          repo,
          targetBranch,
          defaultBranch
        );
      }
      const getFileSha = (await octokit.rest.repos.getContent({
        owner,
        repo,
        path: data.path,
      })) as any;
      const sha = getFileSha.data.sha;
      await octokit.rest.repos.createOrUpdateFileContents({
        owner,
        repo,
        path: data.path,
        message,
        content: Buffer.from(data.content).toString("base64"),
        branch: targetBranch,
        sha,
      });
      return res.json(successResponse(null, "Successfully pushed workflow"));
    } catch (error) {
      console.log(error);
      return res.json(errorResponse("Failed to push workflow"));
    }
  } else if (url.includes("gitlab")) {
    const accessToken = req.user?.thirdParty.find(
      (x) => x.name === "Gitlab"
    )?.accessToken;
    const api = await safeGitlabClient(req.user?._id);
    try {
      const projectData = await api.Projects.show(projectName);
      const defaultBranch = projectData.default_branch;
      const targetBranch = branch || defaultBranch;
      const branchExists = await checkBranchExistsGitlab(
        api,
        projectName,
        targetBranch
      );
      if (!branchExists) {
        // Create the branch if it doesn't exist
        await createBranchGitlab(api, projectName, targetBranch, defaultBranch);
      }
      await api.RepositoryFiles.edit(
        projectName,
        data.path,
        targetBranch,
        data.content,
        message
      );
      return res.json(successResponse(null, "Successfully pushed workflow"));
    } catch (error) {
      console.log(error);
      return res.json(errorResponse("Failed to push workflow"));
    }
  }
}

async function checkBranchExistsGithub(
  octo: OctokitType,
  org: string,
  repo: string,
  branch: string
) {
  try {
    await octo.rest.repos.getBranch({
      owner: org,
      repo,
      branch,
    });
    return true; // Branch exists
  } catch (error: any) {
    if (error.status === 404) {
      return false; // Branch doesn't exist
    }
    throw error; // Other error occurred
  }
}
async function checkBranchExistsGitlab(
  api: GitlabType,
  projectId: string,
  branch: string
) {
  try {
    await api.Branches.show(projectId, branch);
    return true; // Branch exists
  } catch (error: any) {
    return false;
  }
}
async function createBranchGitlab(
  api: GitlabType,
  projectId: string,
  branch: string,
  baseBranch: string
) {
  await api.Branches.create(projectId, branch, baseBranch);
}
async function createBranchGithub(
  octo: OctokitType,
  org: string,
  repo: string,
  branch: string,
  baseBranch: string
) {
  const { data: baseRefData } = await octo.rest.git.getRef({
    owner: org,
    repo,
    ref: `heads/${baseBranch}`,
  });
  const baseCommitSha = baseRefData.object.sha;

  await octo.rest.git.createRef({
    owner: org,
    repo,
    ref: `refs/heads/${branch}`,
    sha: baseCommitSha,
  });
}
