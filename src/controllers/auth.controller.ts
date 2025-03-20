import { ProjectModel, UserModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import { Request, Response } from "express";

export async function logout(req: Request, res: Response) {
  req.logout((err) => {
    if (err) {
      return res.json(errorResponse(err));
    }
  });
  return res.json(successResponse(null, "Logged out"));
}
export async function redirectToHomePage(req: Request, res: Response) {
  const account = req.user;
  if (!account) return;
  try {
    const user = await UserModel.findOne({ account: account._id });
    const firstProject = user?.projectIn[0];
    if (firstProject) {
      const project = await ProjectModel.findById(firstProject);
      if (project) {
        const urlEncodedName = encodeURIComponent(project.name);
        return res.redirect(`${process.env.CLIENT_URL}/${urlEncodedName}/`);
      }
    }
  } catch (err) {
    return res.json(errorResponse("Error redirecting to home page"));
  }
  return res.redirect(`${process.env.CLIENT_URL}/new-project/`);
}
