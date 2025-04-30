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

const phaseRoute = express.Router();

phaseRoute.get("/template", getTemplates);
phaseRoute.post("/template", createPhaseTemplate);
phaseRoute.get("/template/:id", getOneTemplate);
phaseRoute.patch("/template/:id", updateTemplate);
phaseRoute.delete("/template/:id", deleteTemplate);
phaseRoute.get("/:id", get);
phaseRoute.post("/create", createFromTemplate);
phaseRoute.put("/:id", update);
phaseRoute.delete("/:id", remove);
phaseRoute.patch("/:id/task/add/:taskId", addTaskToPhase);
phaseRoute.patch("/:id/task/delete/:taskId", removeTaskFromPhase);
phaseRoute.patch("/:id/artifact/add", addArtifactToPhase);
phaseRoute.patch("/:id/artifact/delete/:artifactId", removeArtifactFromPhase);
phaseRoute.post("/scanner/add", addScannerToPhase);
// phaseRoute.post("/scanner/remove", removeScannerFromPhase); // Commented out as it is not exported
export default phaseRoute;
