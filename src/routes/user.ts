import express from "express";
import {
  get,
  create,
  update,
  remove,
  assignTask,
  getProjectIn,
  addProjectIn,
  getAllUsers,
  adminUpdateUser,
} from "../controllers/user.controller";
import { checkAuth, checkAdmin } from "../middlewares/auth";

const userRoute = express.Router();
userRoute.get("/project", checkAuth, getProjectIn);
userRoute.get("/getAll", getAllUsers);
userRoute.patch("/:id/project", addProjectIn);
userRoute.get("/", get);
userRoute.post("/", create);
userRoute.patch("/", update);
userRoute.patch("/:id/admin-update", checkAuth, checkAdmin, adminUpdateUser);
userRoute.delete("/:id", remove);
userRoute.patch("/:id/assign/:taskId", assignTask);
export default userRoute;
