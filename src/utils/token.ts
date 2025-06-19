import { Gitlab } from "@gitbeaker/rest";
import createOctokitClient from "../octokit";
import axios from "axios";
import { AccountModel } from "../models/models";
import { Types } from "mongoose";

export async function safeGithubClient(accountId: Types.ObjectId | undefined) {
  const account = await AccountModel.findById(accountId);
  const github = account?.thirdParty.find((x) => x.name === "Github");  try {
    const octokit = await createOctokitClient(github?.accessToken || '');
    return octokit;
  } catch (error) {
    // Request a new token from Github
    const response = await axios.post(
      "https://github.com/login/oauth/access_token",
      {
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        grant_type: "refresh_token",
        refresh_token: github?.refreshToken,
      }
    );
    const newAccessToken = response.data.access_token;
    const newRefreshToken = response.data.refresh_token;
    await AccountModel.findByIdAndUpdate(
      accountId,
      {
        $set: {
          "thirdParty.$[elem].accessToken": newAccessToken,
          "thirdParty.$[elem].refreshToken": newRefreshToken,
        },
      },      {
        arrayFilters: [{ "elem.name": "Github" }],
      }    );
    const octokit = await createOctokitClient(newAccessToken);
    return octokit;
  }
}
export async function safeGitlabClient(accountId: Types.ObjectId | undefined) {
  // const account = await AccountModel.findById(accountId);
  // const gitlab = account?.thirdParty.find((x) => x.name === "Gitlab");
  // try {
  //   const api = new Gitlab({ oauthToken: gitlab?.accessToken });
  //   // Try any API call to see if the token is valid
  //   await api.Projects.all({
  //     owned: true,
  //     orderBy: "name",
  //     sort: "asc",
  //   });
  //   return api;
  // } catch (error) {
  //   // Request a new token from Gitlab
  //   const response = await axios.post("https://gitlab.com/oauth/token", {
  //     client_id: process.env.GITLAB_CLIENT_ID,
  //     client_secret: process.env.GITLAB_CLIENT_SECRET,
  //     grant_type: "refresh_token",
  //     refresh_token: gitlab?.refreshToken,
  //   });
  //   const newAccessToken = response.data.access_token;
  //   const newRefreshToken = response.data.refresh_token;
  //   await AccountModel.findByIdAndUpdate(
  //     accountId,
  //     {
  //       $set: {
  //         "thirdParty.$[elem].accessToken": newAccessToken,
  //         "thirdParty.$[elem].refreshToken": newRefreshToken,
  //       },
  //     },
  //     {
  //       arrayFilters: [{ "elem.name": "Gitlab" }],
  //     }
  //   );
  //   const api = new Gitlab({ oauthToken: newAccessToken });
  //   return api;
  }

