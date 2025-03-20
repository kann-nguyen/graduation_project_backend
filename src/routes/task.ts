import express from "express";
import {
  get,
  getAll,
  create,
  update,
  remove,
} from "../controllers/task.controller";
import { checkAuth } from "../middlewares/auth";

const taskRoute = express.Router();

taskRoute.get("/", checkAuth, getAll);
taskRoute.get("/:id", checkAuth, get);
taskRoute.post("/", checkAuth, create);
taskRoute.patch("/:id", checkAuth, update);
taskRoute.delete("/:id", checkAuth, remove);

export default taskRoute;
