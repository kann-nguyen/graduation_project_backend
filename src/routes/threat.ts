import { create, getAll, get, update } from "../controllers/threat.controller";
import express from "express";
const threatRoute = express.Router();
threatRoute.get("/", getAll);
threatRoute.get("/:id", get);
threatRoute.post("/", create);
threatRoute.patch("/:id", update);
export default threatRoute;
