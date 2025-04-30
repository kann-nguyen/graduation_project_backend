import express from "express";
const artifactRoute = express.Router();
import { getAll, get, update, updateRateScan } from "../controllers/artifact.controller";

artifactRoute.get("/", getAll);
artifactRoute.get("/:id", get);
artifactRoute.patch("/:id", update);
artifactRoute.patch("/:id/rate", updateRateScan);
export default artifactRoute;
