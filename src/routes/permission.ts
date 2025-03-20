import express from "express";
import permissions from "../utils/permission";
import { successResponse } from "../utils/responseFormat";
const permissionRoute = express.Router();
permissionRoute.get("/", (req, res) => {
  return res.json(
    successResponse(permissions, "Permissions fetched successfully")
  );
});
export default permissionRoute;
