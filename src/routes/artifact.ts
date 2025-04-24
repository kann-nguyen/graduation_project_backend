import express from "express";
const artifactRoute = express.Router();
import { getAll, get, update } from "../controllers/artifact.controller";

artifactRoute.get("/", getAll);
artifactRoute.get("/:id", get);
artifactRoute.patch("/:id", update);
export default artifactRoute;
