import { create, get, getAll, update, updateState } from "../controllers/ticket.controller";
import express from "express";
import { checkPermission } from "../middlewares/permission";
const ticketRoute = express.Router();

ticketRoute.get("/", checkPermission("ticket:read"), getAll);
ticketRoute.get("/:id", checkPermission("ticket:read"), get);
//ticketRoute.post("/", checkPermission("ticket:create"), create);
ticketRoute.post("/", create);
ticketRoute.patch("/:id", checkPermission("ticket:update"), update);
ticketRoute.patch("/:id/state", updateState);
export default ticketRoute;
