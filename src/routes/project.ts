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
import { checkAuth, checkAdmin, checkProjectManager } from "../middlewares/auth";

const projectRoute = express.Router();

// Read-only routes - accessible to all authenticated users
projectRoute.get("/:projectName", checkAuth, get);
projectRoute.get("/:projectName/member", checkAuth, getProjectMembers);

// Project management routes - require project manager or admin permissions
projectRoute.post("/", checkAuth, checkProjectManager, create);
projectRoute.patch("/:projectName", checkAuth, checkProjectManager, updateStatus);
projectRoute.delete("/:projectName", checkAuth, checkAdmin, remove); // Only admin can delete projects

// Team management routes - require project manager permissions
projectRoute.patch("/:projectName/member", checkAuth, checkProjectManager, addMemberToProject);
projectRoute.delete("/:projectName/member", checkAuth, checkProjectManager, removeMemberFromProject);

export default projectRoute;
