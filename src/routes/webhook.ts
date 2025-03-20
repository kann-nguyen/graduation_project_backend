import express from "express";
import { importVulnToImage } from "../controllers/webhook.controller";
const webhookRoute = express.Router();

webhookRoute.post("/image", importVulnToImage);

export default webhookRoute;
