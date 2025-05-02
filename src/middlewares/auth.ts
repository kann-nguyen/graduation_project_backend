import { NextFunction, Response, Request } from "express";
import { errorResponse } from "../utils/responseFormat";

function checkAuth(req: Request, res: Response, next: NextFunction) {
  if (req.isAuthenticated()) {
    return next();
  }
  return res.status(401).send(errorResponse("You are not authenticated"));
}

function checkAdmin(req: Request, res: Response, next: NextFunction) {
  if (req.user?.role === "admin") {
    return next();
  }
  return res.status(401).send(errorResponse("You are not authorized"));
}

function checkProjectManager(req: Request, res: Response, next: NextFunction) {
  if (req.user?.role === "admin" || req.user?.role === "project_manager") {
    return next();
  }
  return res.status(401).send(errorResponse("Project manager role required"));
}

function checkSecurityExpert(req: Request, res: Response, next: NextFunction) {
  if (req.user?.role === "admin" || req.user?.role === "security_expert") {
    return next();
  }
  return res.status(401).send(errorResponse("Security expert role required"));
}

function checkManagerOrSecurityExpert(req: Request, res: Response, next: NextFunction) {
  if (req.user?.role === "admin" || req.user?.role === "project_manager" || req.user?.role === "security_expert") {
    return next();
  }
  return res.status(401).send(errorResponse("Project manager or security expert role required"));
}

export { 
  checkAuth, 
  checkAdmin, 
  checkProjectManager, 
  checkSecurityExpert,
  checkManagerOrSecurityExpert 
};
