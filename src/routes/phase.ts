import express from "express";
import {
  get,
  createFromTemplate,
  update,
  remove,
  addTaskToPhase,
  removeTaskFromPhase,
  addArtifactToPhase,
  removeArtifactFromPhase,
  getTemplates,
  getOneTemplate,
  updateTemplate,
  deleteTemplate,
  createPhaseTemplate,
  addScannerToPhase,
  //   removeScannerFromPhase, // Commented out as it is not exported
} from "../controllers/phase.controller";
import { checkAuth, checkAdmin, checkProjectManager } from "../middlewares/auth";

const phaseRoute = express.Router();

// Read-only routes accessible to all authenticated users
phaseRoute.get("/template", checkAuth, getTemplates);
phaseRoute.get("/template/:id", checkAuth, getOneTemplate);
phaseRoute.get("/:id", checkAuth, get);

// Phase template management - require admin or project manager permissions
phaseRoute.post("/template", checkAuth, checkProjectManager, createPhaseTemplate);
phaseRoute.patch("/template/:id", checkAuth, checkProjectManager, updateTemplate);
phaseRoute.delete("/template/:id", checkAuth, checkAdmin, deleteTemplate); // Only admin can delete templates

// Phase management - require project manager permissions
phaseRoute.post("/create", checkAuth, checkProjectManager, createFromTemplate);
phaseRoute.put("/:id", checkAuth, checkProjectManager, update);
phaseRoute.delete("/:id", checkAuth, checkProjectManager, remove);

// Task management within phases - require project manager permissions
phaseRoute.patch("/:id/task/add/:taskId", checkAuth, checkProjectManager, addTaskToPhase);
phaseRoute.patch("/:id/task/delete/:taskId", checkAuth, checkProjectManager, removeTaskFromPhase);

// Artifact management within phases - require project manager permissions
phaseRoute.patch("/:id/artifact/add", checkAuth, checkProjectManager, addArtifactToPhase);
phaseRoute.patch("/:id/artifact/delete/:artifactId", checkAuth, checkProjectManager, removeArtifactFromPhase);

// Scanner management - require project manager permissions
phaseRoute.post("/scanner/add", checkAuth, checkProjectManager, addScannerToPhase);
// phaseRoute.post("/scanner/remove", checkAuth, checkProjectManager, removeScannerFromPhase); // Commented out as it is not exported

export default phaseRoute;
