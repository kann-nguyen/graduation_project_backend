import express from "express";
import {
  addMemberToProject,
  create,
  get,
  getProjectMembers,
  remove,
  removeMemberFromProject,
  updateStatus,
} from "../controllers/project.controller";

const projectRoute = express.Router();

projectRoute.get("/:projectName", get);
projectRoute.post("/", create);
projectRoute.patch("/:projectName", updateStatus);
projectRoute.delete("/:projectName", remove);
projectRoute.get("/:projectName/member", getProjectMembers);
projectRoute.patch("/:projectName/member", addMemberToProject);
projectRoute.delete("/:projectName/member", removeMemberFromProject);
export default projectRoute;
