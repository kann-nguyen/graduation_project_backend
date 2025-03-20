import express from "express";
import {
  getWorkflows,
  pushNewWorkflow,
} from "../controllers/workflow.controller";
const workflowRoute = express.Router();

workflowRoute.get("/", getWorkflows);

workflowRoute.post("/", pushNewWorkflow);

export default workflowRoute;
