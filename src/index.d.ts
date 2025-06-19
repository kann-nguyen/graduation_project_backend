import { Account } from "../src/models/account";
import { Gitlab } from "@gitbeaker/rest";
import createOctokitClient from "./octokit";

declare global {
  namespace Express {
    interface User extends Account {}
  }
}
export {};
export type GitlabType = InstanceType<typeof Gitlab>;
// Define OctokitType as the return type of createOctokitClient
export type OctokitType = Awaited<ReturnType<typeof createOctokitClient>>;
