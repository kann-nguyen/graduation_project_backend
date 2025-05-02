import { Request, Response } from "express";
import mongoose from "mongoose";
import { MitigationModel, ThreatModel } from "../models/models";
import { errorResponse, successResponse } from "../utils/responseFormat";

/**
 * Get all mitigations
 * 
 * @param {Request} req - The request
 * @param {Response} res - The response
 * @returns {Promise<Response>} - JSON response with all mitigations
 */
export async function getAll(req: Request, res: Response) {
  try {
    const mitigations = await MitigationModel.find();
    return res.json(successResponse(mitigations, "Mitigations retrieved successfully"));
  } catch (error) {
    console.error("Error retrieving mitigations:", error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Get mitigations for a specific threat
 * 
 * @param {Request} req - The request with threat ID
 * @param {Response} res - The response
 * @returns {Promise<Response>} - JSON response with the mitigations for the threat
 */
export async function get(req: Request, res: Response) {
    const threatId = req.params.threatId;
    console.log(`Retrieving mitigations for threat ID: ${req.params.threatId}`);

    try {
      // Validate ID
      if (!mongoose.Types.ObjectId.isValid(threatId)) {
        console.log(`Invalid threat ID format: ${threatId}`);
        return res.json(errorResponse("Invalid threat ID format"));
      }
  
      // Find the threat and fully populate its mitigations with all fields
      console.log(`Finding threat with ID: ${threatId}`);
      const threat = await ThreatModel.findById(threatId).populate({
        path: 'mitigations',
        model: 'Mitigation',
        populate: {
          path: 'createdBy',
          model: 'User',
          select: 'name email'
        }
      });
  
      console.log(`Threat found: ${threat ? 'Yes' : 'No'}`);
      if (!threat) {
        return res.json(errorResponse("Threat not found"));
      }
  
      console.log(`Number of mitigations found: ${threat.mitigations?.length || 0}`);
      return res.json(successResponse(threat.mitigations, "Threat mitigations retrieved successfully"));
    } catch (error) {
      console.error(`Error retrieving mitigations for threat with ID ${threatId}:`, error);
      return res.json(errorResponse(`Internal server error: ${error}`));
    }
}

/**
 * Create a new mitigation
 * 
 * @param {Request} req - The request with mitigation data
 * @param {Response} res - The response
 * @returns {Promise<Response>} - JSON response with the created mitigation
 */
export async function create(req: Request, res: Response) {
  const { title, description, implementation, threatId } = req.body.data;
  const userId = req.user?._id;

  try {
    // Validate required fields
    if (!title || !description || !implementation) {
      return res.json(errorResponse("Missing required mitigation fields"));
    }

    // Create the mitigation
    const newMitigation = await MitigationModel.create({
      title,
      description,
      implementation,
      createdBy: userId
    });

    // If a threatId is provided, add the mitigation to the threat
    if (threatId && mongoose.Types.ObjectId.isValid(threatId)) {
      await ThreatModel.findByIdAndUpdate(
        threatId,
        { $push: { mitigations: newMitigation._id } }
      );
    }

    // Fetch the created mitigation with populated creator info
    const populatedMitigation = await MitigationModel.findById(newMitigation._id).populate({
      path: 'createdBy',
      model: 'User',
      select: 'name email'
    });

    return res.json(successResponse(populatedMitigation, "Mitigation created successfully"));
  } catch (error) {
    console.error("Error creating mitigation:", error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Update an existing mitigation
 * 
 * @param {Request} req - The request with mitigation ID and updated data
 * @param {Response} res - The response
 * @returns {Promise<Response>} - JSON response with the updated mitigation
 */
export async function update(req: Request, res: Response) {
  const { id } = req.params;
  const { title, description, implementation } = req.body.data;
  
  console.log(`Updating mitigation with ID: ${id}`);
  console.log(`Update data:`, { title, description, implementation });

  try {
    // Validate ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      console.log(`Invalid mitigation ID format: ${id}`);
      return res.json(errorResponse("Invalid mitigation ID format"));
    }

    // Check if at least one field is provided
    if (!title && !description && !implementation) {
      console.log(`No fields provided for update`);
      return res.json(errorResponse("No fields to update provided"));
    }

    // Create an update object with only the provided fields
    const updateData: any = {};
    if (title) updateData.title = title;
    if (description) updateData.description = description;
    if (implementation) updateData.implementation = implementation;
    
    console.log(`Update data object created:`, updateData);

    // Update the mitigation
    console.log(`Attempting to update mitigation in database...`);
    const updatedMitigation = await MitigationModel.findByIdAndUpdate(
      id,
      updateData,
      { new: true }
    ).populate({
      path: 'createdBy',
      model: 'User',
      select: 'name email'
    });
    
    console.log(`Update result:`, updatedMitigation ? 'Mitigation updated successfully' : 'Mitigation not found');

    if (!updatedMitigation) {
      return res.json(errorResponse("Mitigation not found"));
    }

    return res.json(successResponse(updatedMitigation, "Mitigation updated successfully"));
  } catch (error) {
    console.error(`Error updating mitigation with ID ${id}:`, error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}

/**
 * Delete a mitigation
 * 
 * @param {Request} req - The request with mitigation ID
 * @param {Response} res - The response
 * @returns {Promise<Response>} - JSON response with deletion confirmation
 */
export async function remove(req: Request, res: Response) {
  const { id } = req.params;

  try {
    // Validate ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.json(errorResponse("Invalid mitigation ID format"));
    }

    // Remove the mitigation from any threats referencing it
    await ThreatModel.updateMany(
      { mitigations: id },
      { $pull: { mitigations: id } }
    );

    // Delete the mitigation
    const deletedMitigation = await MitigationModel.findByIdAndDelete(id);

    if (!deletedMitigation) {
      return res.json(errorResponse("Mitigation not found"));
    }

    return res.json(successResponse(null, "Mitigation deleted successfully"));
  } catch (error) {
    console.error(`Error deleting mitigation with ID ${id}:`, error);
    return res.json(errorResponse(`Internal server error: ${error}`));
  }
}