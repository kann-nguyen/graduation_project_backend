import express from "express";
import { importVulnToDocs, importVulnToImage } from "../controllers/webhook.controller";
const webhookRoute = express.Router();

webhookRoute.post("/image", importVulnToImage);


webhookRoute.post("/docs", importVulnToDocs);

export default webhookRoute;
