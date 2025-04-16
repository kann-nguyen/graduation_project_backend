import express from "express";
const artifactRoute = express.Router();
import { getAll, get, update, generateAndAttachThreats1 } from "../controllers/artifact.controller";

artifactRoute.get("/", getAll);
artifactRoute.get("/:id", get);
artifactRoute.patch("/:id", update);
artifactRoute.post("/:id/threat", generateAndAttachThreats1);
export default artifactRoute;
