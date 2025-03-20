import { NextFunction, Request, Response } from "express";

export function checkPermission(permission: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.user && req.user.permission.includes(permission)) {
      next();
    } else {
      res.status(403).send("Forbidden");
    }
  };
}
