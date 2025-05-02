import { create, getAll, get, update, recalculateZeroScores } from "../controllers/threat.controller";
import express from "express";
import { getDetailedThreatInfo, getSuggestedFixes } from "../controllers/threatModeling.controller";
import { updateRateScan } from "../controllers/artifact.controller";
import { checkAuth, checkManagerOrSecurityExpert } from "../middlewares/auth";

const threatRoute = express.Router();

// Public routes
threatRoute.get("/", checkAuth, getAll);
threatRoute.get("/:id", checkAuth, get);

// Protected routes - require project manager or security expert role
threatRoute.post("/", checkAuth, checkManagerOrSecurityExpert, create);
threatRoute.patch("/:id", checkAuth, checkManagerOrSecurityExpert, update);
threatRoute.get("/:id/model_details", checkAuth, getDetailedThreatInfo);
threatRoute.get("/:id/model_suggest", checkAuth, getSuggestedFixes);
threatRoute.post("/recalculate_scores", checkAuth, checkManagerOrSecurityExpert, recalculateZeroScores);

export default threatRoute;
