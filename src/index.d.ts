import { Account } from "../src/models/account";
import { Gitlab } from "@gitbeaker/rest";
import MyOctokit from "./octokit";

declare global {
  namespace Express {
    interface User extends Account {}
  }
}
export {};
export type GitlabType = InstanceType<typeof Gitlab>;
export type OctokitType = InstanceType<typeof MyOctokit>;
