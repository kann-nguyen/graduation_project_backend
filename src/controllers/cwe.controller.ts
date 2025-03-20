import { Request, Response } from "express";
import { CWEModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";

export async function get(req: Request, res: Response) {
  const { id } = req.params;
  // id is in full form. Search for it using only the index number instead
  const index = id.split("-")[1];
  try {
    const cwe = await CWEModel.findOne({ cweId: index });
    if (!cwe)
      return res.json(errorResponse("CWE is not found in the database"));
    return res.json(successResponse(cwe, "CWE found"));
  } catch (error) {
    return res.json(error);
  }
}
