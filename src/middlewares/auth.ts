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
export { checkAuth, checkAdmin };
