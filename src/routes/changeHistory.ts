import express from "express";
import {
  getAdminChangeHistory,
  getChangeHistoryByObjectId,
} from "../controllers/changeHistory.controller";
const changeHistoryRoute = express.Router();
changeHistoryRoute.get("/", getAdminChangeHistory);
changeHistoryRoute.get("/:objectId", getChangeHistoryByObjectId);
export default changeHistoryRoute;
