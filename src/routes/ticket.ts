import { create, get, getAll, update, updateState } from "../controllers/ticket.controller";
import express from "express";
import { checkPermission } from "../middlewares/permission";
import { checkAuth, checkSecurityExpert, checkManagerOrSecurityExpert } from "../middlewares/auth";

const ticketRoute = express.Router();

// Basic authenticated routes with permission checks
ticketRoute.get("/", checkAuth, checkPermission("ticket:read"), getAll);
ticketRoute.get("/:id", checkAuth, checkPermission("ticket:read"), get);

// Routes that allow both security experts and users with appropriate permissions
ticketRoute.post("/", checkAuth, create);
ticketRoute.patch("/:id", checkAuth, checkPermission("ticket:update"), update);

// State changes can be initiated by security experts or users with the right permissions
ticketRoute.patch("/:id/state", checkAuth, updateState);

export default ticketRoute;
