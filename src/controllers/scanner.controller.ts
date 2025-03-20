import { Request, Response } from "express";
import { ChangeHistoryModel, ScannerModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";
import {
  generateDockerfile,
  sampleCode,
  vulnInterface,
} from "../utils/generateDockerfile";

export async function getAll(req: Request, res: Response) {
  const { createdBy } = req.query;
  try {
    if (!createdBy) {
      const scanners = await ScannerModel.find();
      return res.json(successResponse(scanners, "Scanners found"));
    }
    const scanners = await ScannerModel.find({ createdBy });
    return res.json(successResponse(scanners, "Scanners found"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function create(req: Request, res: Response) {
  const { data } = req.body;
  try {
    const scanner = await ScannerModel.findOne({ name: data.name });
    if (scanner) {
      return res.json(errorResponse("Scanner already exists"));
    }
    const newScanner = await ScannerModel.create({
      name: data.name,
      createdBy: req.user?.username,
      config: data.config,
    });
    const dockerfile = await generateDockerfile(data.config);
    await ChangeHistoryModel.create({
      objectId: newScanner._id,
      action: "create",
      timestamp: Date.now(),
      description: `Account ${req.user?.username} create a new scanner`,
      account: req.user?._id,
    });
    return res.json(successResponse(dockerfile, "Scanner created"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function getSampleCode(req: Request, res: Response) {
  return res.json(
    successResponse(
      {
        interface: vulnInterface,
        sampleCode: sampleCode,
      },
      "Sample code found"
    )
  );
}

export async function get(req: Request, res: Response) {
  const { id } = req.params;
  try {
    const scanner = await ScannerModel.findById(id);
    return res.json(successResponse(scanner, "Scanner found"));
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

export async function update(req: Request, res: Response) {
  const { data } = req.body;
  try {
    await ScannerModel.findOneAndUpdate(
      {
        name: data.name,
      },
      {
        config: {
          installCommand: data.config.installCommand,
          code: data.config.code,
        },
      }
    );
    const dockerfile = await generateDockerfile(data.config);
    return res.json(
      successResponse(
        dockerfile,
        "Scanner updated. New Dockerfile content is copied to your clipboard!"
      )
    );
  } catch (error) {
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}
