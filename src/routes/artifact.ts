import express from "express";
const artifactRoute = express.Router();
import { getAll, get, update, updateRateScan, getPhaseForArtifact } from "../controllers/artifact.controller";

artifactRoute.get("/", getAll);
artifactRoute.get("/:id", get);
artifactRoute.get("/:id/phase", getPhaseForArtifact);
artifactRoute.patch("/:id", update);
artifactRoute.patch("/:id/rate", updateRateScan);
export default artifactRoute;
