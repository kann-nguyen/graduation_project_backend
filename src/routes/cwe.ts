import { get } from "../controllers/cwe.controller";
import express from "express";
const cweRoute = express.Router();

cweRoute.get("/:id", get);
export default cweRoute;
