import express from "express";
import {
  getAll,
  get,
  create,
  update,
  remove,
  getReposFromGithub,
  getReposFromGitlab,
} from "../controllers/thirdParty.controller";

const thirdPartyRoute = express.Router();

thirdPartyRoute.get("/", getAll);
thirdPartyRoute.get("/:id", get);
thirdPartyRoute.post("/", create);
thirdPartyRoute.put("/:id", update);
thirdPartyRoute.delete("/:id", remove);
thirdPartyRoute.get("/github/repo", getReposFromGithub);
thirdPartyRoute.get("/gitlab/repo", getReposFromGitlab);
export default thirdPartyRoute;
