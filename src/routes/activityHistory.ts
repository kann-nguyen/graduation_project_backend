import express from "express";
import { getActivityHistory } from "../controllers/activityHistory.controller";
import { checkAuth } from "../middlewares/auth";

const activityHistoryRoute = express.Router();
activityHistoryRoute.get("/:projectName", checkAuth, getActivityHistory);
export default activityHistoryRoute;
