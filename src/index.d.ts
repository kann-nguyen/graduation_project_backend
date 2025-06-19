import { Account } from "../src/models/account";
import { Gitlab } from "@gitbeaker/rest";
import getOctokit from "./octokit";

declare global {
  namespace Express {
    interface User extends Account {}
  }
}
export {};
export type GitlabType = InstanceType<typeof Gitlab>;
// Updated to handle the async function that returns Octokit
export type OctokitType = Awaited<ReturnType<typeof getOctokit>>;
