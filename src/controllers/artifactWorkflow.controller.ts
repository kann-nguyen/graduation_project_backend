import { Request, Response } from 'express';
import { ArtifactModel, TicketModel } from '../models/models';
import { Artifact } from '../models/artifact';
import mongoose from 'mongoose';
import { Ticket } from '../models/ticket';

export class ArtifactWorkflowController {    
  public static async getWorkflowHistory(req: Request, res: Response) {
    try {
      const { artifactId } = req.params;
      
      const history = await ArtifactWorkflowController._getWorkflowHistory(artifactId);
      return res.status(200).json({
        success: true,
        data: history
      });
    } catch (error: any) {
      return res.status(500).json({
        success: false,
        message: error.message || 'Failed to fetch workflow history'
      });
    }
  }
  public static async getProjectWorkflowStats(req: Request, res: Response) {
    try {
      const { projectId } = req.params;
      
      const stats = await ArtifactWorkflowController._getProjectWorkflowStats(projectId);
      
      return res.status(200).json({
        success: true,
        data: stats
      });
    } catch (error: any) {
      return res.status(500).json({
        success: false,
        message: error.message || 'Failed to fetch project workflow stats'
      });
    }
  }
  public static async getArtifactsByWorkflowStep(req: Request, res: Response) {
    try {
      const { projectId } = req.params;
      const { step } = req.query;
      
      const stepNumber = step ? parseInt(step as string) : undefined;
      
      // Find artifacts in the specified project and step
      const query: any = { projectId };
      if (stepNumber && stepNumber >= 1 && stepNumber <= 5) {
        query.currentWorkflowStep = stepNumber;
      }
      
      const artifacts = await ArtifactModel.find(query);
      
      return res.status(200).json({
        success: true,
        data: artifacts
      });
    } catch (error: any) {
      return res.status(500).json({
        success: false,
        message: error.message || 'Failed to fetch artifacts by workflow step'
      });
    }
  }
  private static async _initializeWorkflowCycle(artifactId: string | mongoose.Types.ObjectId) {
    console.log(`[INFO] Initializing new workflow cycle for artifact: ${artifactId}`);
    
    // Get the latest artifact data
    const artifact = await ArtifactModel.findById(artifactId);
    if (!artifact) {
      throw new Error('Artifact not found');
    }    // First, check if we need to increment the workflow cycle count
    const lastCyclesCount = artifact.workflowCyclesCount || 0;
    const cycleNumber = lastCyclesCount + 1;
    
    console.log(`[DEBUG] Creating new workflow cycle #${cycleNumber} (previous cycles count: ${lastCyclesCount})`);
    
    // Initialize new cycle with all required fields
    const newCycle = {
      cycleNumber,
      currentStep: 1, // Start at step 1 (Detection)
      startedAt: new Date(),
      // Initialize all steps to ensure they exist in both currentWorkflowCycle and workflowCycles array
      detection: {
        completedAt: new Date(), // Detection is completed when the cycle starts
        numberVuls: artifact.vulnerabilityList?.length || 0, // Initialize with current vulnerability count
        listVuls: []
      },
      classification: {
        numberThreats: artifact.threatList?.length || 0, // Initialize with current threat count
        listThreats: []
      },
      assignment: {
        numberTicketsAssigned: 0,
        numberTicketsNotAssigned: 0,
        listTickets: []
      },
      remediation: {
        numberTicketsSubmitted: 0, 
        numberTicketsNotSubmitted: 0,
        numberThreatsResolved: 0,
        listTickets: []
      },
      verification: {
        numberTicketsResolved: 0,
        numberTicketsReturnedToProcessing: 0
      }
    };
    
    // Create a deep copy for pushing to the workflow cycles array
    const deepCopy = JSON.parse(JSON.stringify(newCycle));
    
    // Check if we already have this cycle in the array to avoid duplicates
    const existingCycle = artifact.workflowCycles?.find(
      (c: any) => c.cycleNumber === cycleNumber
    );
    
    let updateOperation: any = { 
      $set: {
        workflowCyclesCount: cycleNumber,  // Set directly to the current cycle number
        currentWorkflowStep: 1,
        workflowCompleted: false,
        currentWorkflowCycle: newCycle
      }
    };
    
    // Only push to array if this cycle doesn't exist yet
    if (!existingCycle) {
      updateOperation.$push = { workflowCycles: deepCopy };
    }
    
    console.log(`[DEBUG] Applying workflow update:`, {
      cycleNumber,
      existingCycle: existingCycle ? 'yes' : 'no',
      willPush: !existingCycle
    });
    
    // Use findOneAndUpdate with an atomic operation to ensure consistency
    const updatedArtifact = await ArtifactModel.findOneAndUpdate(
      { _id: artifact._id },
      updateOperation,
      { 
        new: true,  // Return the updated document
        runValidators: true  // Run schema validators
      }
    );
      if (!updatedArtifact) {
      throw new Error(`Failed to initialize workflow cycle for artifact ${artifact._id}`);
    }
    
    // Verify that the cycle was properly created/updated
    const finalCheck = await ArtifactModel.findById(artifact._id);
    if (finalCheck) {
      // Check if currentWorkflowCycle matches what we expect
      if (!finalCheck.currentWorkflowCycle || finalCheck.currentWorkflowCycle.cycleNumber !== cycleNumber) {
        console.log(`[WARN] Workflow cycle verification failed:`, {
          expected: cycleNumber,
          actual: finalCheck.currentWorkflowCycle?.cycleNumber,
          workflowCyclesCount: finalCheck.workflowCyclesCount,
          cyclesInArray: finalCheck.workflowCycles?.length
        });
        
        // Try to fix if needed
        if (!finalCheck.currentWorkflowCycle) {
          console.log(`[INFO] Auto-fixing: currentWorkflowCycle was not set`);
          await ArtifactModel.findByIdAndUpdate(
            artifact._id,
            { $set: { currentWorkflowCycle: newCycle } }
          );
        }
      } else {
        console.log(`[INFO] Workflow cycle #${cycleNumber} successfully initialized`);
      }
    }
    
    return updatedArtifact;
  }

  private static async _moveToNextStep(artifactId: string | mongoose.Types.ObjectId, stepData: any = {}) {
    console.log(`[WorkflowController:_moveToNextStep] Starting for artifact: ${artifactId}`);
    
    const artifact = await ArtifactModel.findById(artifactId);    
    if (!artifact) {
      throw new Error('Artifact not found');
    }

    if (!artifact.currentWorkflowCycle) {
      throw new Error('No active workflow cycle');
    }

    const currentStep = artifact.currentWorkflowStep || 1;
    let nextStep = currentStep + 1;
    
    // Update the current step data with completion timestamp
    const updatedStepData = {
      ...stepData,
      completedAt: new Date()
    };
    
    // Update current step data
    this._updateStepData(artifact, currentStep, updatedStepData);    // Check if we've completed all steps
    if (nextStep > 5) {
      console.log(`[INFO] Completed all steps for cycle #${artifact.currentWorkflowCycle.cycleNumber}`);
      
      // Mark the current cycle as completed using atomic update
      await ArtifactModel.findByIdAndUpdate(
        artifact._id,
        { 
          $set: {
            'currentWorkflowCycle.completedAt': new Date(),
            workflowCyclesCount: artifact.currentWorkflowCycle.cycleNumber, // Ensure count is correctly set
            workflowCompleted: true
          }
        },
        { new: true }
      );
      
      // Start a new workflow cycle with a fresh artifact state
      console.log(`[INFO] Starting new workflow cycle for artifact ${artifact._id}`);
      return await ArtifactWorkflowController._initializeWorkflowCycle(artifact._id);
    }

    // Update the current step
    artifact.currentWorkflowStep = nextStep;
    artifact.currentWorkflowCycle.currentStep = nextStep;    // Final sync to ensure all data is consistent
    this._syncWorkflowCycles(artifact);
    // Validate workflow consistency
    this._validateWorkflowConsistency(artifact);
    await artifact.save();
    
    return artifact;
  }

  private static async _getWorkflowHistory(artifactId: string | mongoose.Types.ObjectId) {
    const artifact = await ArtifactModel.findById(artifactId);
    if (!artifact) {
      throw new Error('Artifact not found');
    }

    return artifact.workflowCycles || [];
  }

  private static async _getProjectWorkflowStats(projectId: string | mongoose.Types.ObjectId) {
    const artifacts = await ArtifactModel.find({ projectId });
    
    const stats = {
      totalArtifacts: artifacts.length,
      step1Count: 0,
      step2Count: 0,
      step3Count: 0,
      step4Count: 0,
      step5Count: 0,
      completedArtifacts: 0,
      totalCycles: 0,
      averageCycles: 0,
    };

    artifacts.forEach(artifact => {
      const step = artifact.currentWorkflowStep || 1;
      
      // Count artifacts by current step
      if (step === 1) stats.step1Count++;
      if (step === 2) stats.step2Count++;
      if (step === 3) stats.step3Count++;
      if (step === 4) stats.step4Count++;
      if (step === 5) stats.step5Count++;

      // Count completed artifacts
      if (artifact.workflowCompleted) {
        stats.completedArtifacts++;
      }

      // Sum up total cycles
      stats.totalCycles += artifact.workflowCyclesCount || 0;
    });

    // Calculate average cycles per artifact
    stats.averageCycles = stats.totalArtifacts > 0 
      ? stats.totalCycles / stats.totalArtifacts 
      : 0;

    return stats;
  }
  private static _updateStepData(artifact: Artifact, step: number, data: any) {
    if (!artifact.currentWorkflowCycle) {
      return false;
    }
    
    try {
      switch (step) {
        case 1:
          artifact.currentWorkflowCycle.detection = {
            ...artifact.currentWorkflowCycle.detection,
            ...data
          };
          break;
        case 2:
          if (!artifact.currentWorkflowCycle.classification) {
            artifact.currentWorkflowCycle.classification = {};
          }
          artifact.currentWorkflowCycle.classification = {
            ...artifact.currentWorkflowCycle.classification,
            ...data
          };
          break;
        case 3:
          if (!artifact.currentWorkflowCycle.assignment) {
            artifact.currentWorkflowCycle.assignment = {};
          }
          artifact.currentWorkflowCycle.assignment = {
            ...artifact.currentWorkflowCycle.assignment,
            ...data
          };
          break;
        case 4:
          if (!artifact.currentWorkflowCycle.remediation) {
            artifact.currentWorkflowCycle.remediation = {};
          }
          artifact.currentWorkflowCycle.remediation = {
            ...artifact.currentWorkflowCycle.remediation,
            ...data
          };
          break;
        case 5:
          if (!artifact.currentWorkflowCycle.verification) {
            artifact.currentWorkflowCycle.verification = {};
          }
          artifact.currentWorkflowCycle.verification = {
            ...artifact.currentWorkflowCycle.verification,
            ...data
          };
          break;
        default:
          console.warn(`[WorkflowController:_updateStepData] Invalid step number: ${step}`);
          return false;
      }
        // Synchronize the workflow cycles array with the current workflow cycle
      this._syncWorkflowCycles(artifact);
      
      return true;
    } catch (error) {
      console.error(`[WorkflowController:_updateStepData] Error updating step ${step} data:`, error);
      return false;
    }
  }


  public static async updateWorkflowStatus(artifactId: string | mongoose.Types.ObjectId, step: number): Promise<any> {
    const artifact = await ArtifactModel.findById(artifactId)
      .populate('threatList')
      .populate({
        path: 'vulnerabilityList',
        model: 'Vulnerability'
      });

    if (!artifact) {
      throw new Error('Artifact not found');
    }

    // Initialize workflow cycle if none exists
    if (!artifact.currentWorkflowCycle) {
      return await ArtifactWorkflowController._initializeWorkflowCycle(artifactId);
    }
    
    console.log(`[INFO] Start update for step: ${step}`);
    // Check conditions for each step and update as necessary
    switch (step) {
      case 1: // Detection step
        return await ArtifactWorkflowController._checkDetectionStepCompletion(artifact);
      
      case 2: // Classification step
        return await ArtifactWorkflowController._checkClassificationStepCompletion(artifact);
      
      case 3: // Assignment step
        return await ArtifactWorkflowController._checkAssignmentStepCompletion(artifact);
      
      case 4: // Remediation step
        return await ArtifactWorkflowController._checkRemediationStepCompletion(artifact);
      
      case 5: // Verification step
        return await ArtifactWorkflowController._checkVerificationStepCompletion(artifact);
      
      default:
        artifact.currentWorkflowStep = 1;
        await artifact.save();
        return artifact;
    }
  }

  private static async _checkDetectionStepCompletion(artifact: any): Promise<any> {
      // If artifact is still scanning, we can't move forward yet
    if (artifact.isScanning) {
      return artifact;
    }
    
    // If there are no vulnerabilities, we still consider it complete but note this
    const vulnCount = artifact.vulnerabilityList?.length || 0;
    
    // Update detection step data
    if (artifact.currentWorkflowCycle && artifact.currentWorkflowCycle.detection) {
      artifact.currentWorkflowCycle.detection.listVuls = artifact.vulnerabilityList;
      artifact.currentWorkflowCycle.detection.numberVuls = vulnCount;
      artifact.currentWorkflowCycle.detection.completedAt = new Date(); // Move to next step
      // Sync workflow cycles to ensure data consistency
      this._syncWorkflowCycles(artifact);
    }
    await artifact.save();
    // Move to classification step
    if (artifact.currentWorkflowStep === 1) 
      return await ArtifactWorkflowController._moveToNextStep(artifact._id);
  }

  private static async _checkClassificationStepCompletion(artifact: any): Promise<any> {
    // Count threat
    const threatCount = artifact.threatList?.length || 0;
    
    // If we have threats, update classification step data and move forward
    if (threatCount > 0) {
      // Update classification step data
      if (artifact.currentWorkflowCycle) {
        if (!artifact.currentWorkflowCycle.classification) {
          artifact.currentWorkflowCycle.classification = {};
        }        // Log the threats before updating
        
        // Store threat IDs in the classification step data
        artifact.currentWorkflowCycle.classification.listThreats = artifact.threatList.map((threat: any) => 
          typeof threat === 'object' ? threat._id : threat
        );
        artifact.currentWorkflowCycle.classification.numberThreats = threatCount;
        artifact.currentWorkflowCycle.classification.completedAt = new Date();
        
        // Sync workflow cycles to ensure data consistency
        this._syncWorkflowCycles(artifact);
        
        await artifact.save();
      
      }
      if (artifact.currentWorkflowStep === 2) 
        return await ArtifactWorkflowController._moveToNextStep(artifact._id);
    }
      // If no threats, check if we need to mark detection as complete anyway
    // This happens if all vulnerabilities were resolved in a previous cycle
    const vulnerabilityCount = artifact.vulnerabilityList?.length || 0;
    if (vulnerabilityCount === 0 && threatCount === 0) {
      artifact.workflowCompleted = true;
      await artifact.save();
    }
    
    return artifact;
  }

  private static async _checkAssignmentStepCompletion(artifact: any): Promise<any> {    
    // Get ticket counts and lists
    const {
      tickets,
      assigned: assignedTickets,
      unassigned: unassignedTickets
    } = await ArtifactWorkflowController._getTicketCounts(artifact._id);
        
    // Update assignment step data
    if (artifact.currentWorkflowCycle) {
      if (!artifact.currentWorkflowCycle.assignment) {
        artifact.currentWorkflowCycle.assignment = {};
      }
      
      artifact.currentWorkflowCycle.assignment.listTickets = tickets.map((t: any) => t._id);
      artifact.currentWorkflowCycle.assignment.numberTicketsAssigned = assignedTickets.length;
      artifact.currentWorkflowCycle.assignment.numberTicketsNotAssigned = unassignedTickets.length;
      
      await artifact.save();
    }
    
    // If at least one ticket is assigned, move to remediation step
    if (assignedTickets.length > 0) {
      if (artifact.currentWorkflowStep === 3) 
        return await ArtifactWorkflowController._moveToNextStep(artifact._id);
    }
    
    return artifact;
  }

  private static async _checkRemediationStepCompletion(artifact: any): Promise<any> {      // Get ticket counts and lists using our utility method
    const {
      tickets,
      submitted: submittedTickets,
      notSubmitted: notSubmittedTickets,
      resolved: resolvedTickets
    } = await ArtifactWorkflowController._getTicketCounts(artifact._id);
        
    // Update remediation step data
    if (artifact.currentWorkflowCycle) {
      if (!artifact.currentWorkflowCycle.remediation) {
        artifact.currentWorkflowCycle.remediation = {};
      }
      
      artifact.currentWorkflowCycle.remediation.listTickets = tickets.map((t: any) => t._id);
      artifact.currentWorkflowCycle.remediation.numberTicketsSubmitted = submittedTickets.length;
      artifact.currentWorkflowCycle.remediation.numberTicketsNotSubmitted = notSubmittedTickets.length;
      artifact.currentWorkflowCycle.remediation.completedAt = submittedTickets.length > 0 ? new Date() : undefined;
      
      await artifact.save();
    }
    
    // If at least one ticket is submitted/resolved, move to verification step
    if (submittedTickets.length > 0) {
      if (artifact.currentWorkflowStep === 4) 
        return await ArtifactWorkflowController._moveToNextStep(artifact._id);
    }
    
    return artifact;
  }

  private static async _checkVerificationStepCompletion(artifact: any): Promise<any> {    
    // If the artifact is still scanning, it's in the verification process
    console.log(`[INFO] Checking verification for artifact: ${artifact._id}`);
    if (artifact.isScanning) {
      return artifact;
    }
      // Get ticket counts and lists using our utility method
    const {
      tickets,
      resolved: resolvedTickets,
      returned: returnedTickets    } = await ArtifactWorkflowController._getTicketCounts(artifact._id);
    
    console.log(`[INFO] resolvedTickets: ${resolvedTickets.length}`);
    console.log(`[INFO] returnedTickets: ${returnedTickets.length}`);    // Update verification step data using findOneAndUpdate to avoid version conflicts
    if (artifact.currentWorkflowCycle) {
      // Prepare verification data
      const verificationData: any = {
        'currentWorkflowCycle.verification.numberTicketsResolved': resolvedTickets.length,
        'currentWorkflowCycle.verification.numberTicketsReturnedToProcessing': returnedTickets.length,
        'currentWorkflowCycle.verification.completedAt': new Date()
      };
      
      // Update using findOneAndUpdate to avoid version conflicts
      await ArtifactModel.findByIdAndUpdate(
        artifact._id,
        { $set: verificationData },
        { new: true }
      );
      
      // Get fresh artifact data after update
      artifact = await ArtifactModel.findById(artifact._id);
    }
    
    // Complete this workflow cycle and potentially start a new one    // Check if any issues require another cycle
    if (returnedTickets.length > 0 || artifact.vulnerabilityList?.length > 0) {
      console.log(`[INFO] START NEW CYCLE`);
      
      // Get a fresh artifact before starting a new cycle to ensure we have the latest data
      const freshArtifact = await ArtifactModel.findById(artifact._id);
      if (!freshArtifact) {
        throw new Error(`Failed to retrieve artifact ${artifact._id} before starting new cycle`);
      }
      
      console.log(`[DEBUG] Current workflow data before new cycle:`, {
        cyclesCount: freshArtifact.workflowCyclesCount,
        currentStep: freshArtifact.currentWorkflowStep,
        cyclesLength: freshArtifact.workflowCycles?.length
      });
      
      // CRITICAL: First ensure the current cycle is saved to the workflowCycles array
      if (freshArtifact.currentWorkflowCycle) {
        const currentCycle = freshArtifact.currentWorkflowCycle;
        const cycleNumber = currentCycle.cycleNumber;
        
        console.log(`[INFO] Ensuring current cycle #${cycleNumber} is saved to workflowCycles array`);
        
        // Mark the current cycle as completed
        currentCycle.completedAt = new Date();
        
        // Find if this cycle already exists in the array
        const existingCycleIndex = freshArtifact.workflowCycles?.findIndex(
          (c: any) => c.cycleNumber === cycleNumber
        ) ?? -1;
        
        // Create a clean deep copy
        const cycleCopy = JSON.parse(JSON.stringify(currentCycle));
        
        // Update operation - either update the existing cycle or push a new one
        let updateOp: any;
        
        if (existingCycleIndex >= 0) {
          // Update existing cycle
          updateOp = { 
            $set: { [`workflowCycles.${existingCycleIndex}`]: cycleCopy }
          };
          console.log(`[DEBUG] Updating existing cycle at index ${existingCycleIndex}`);
        } else {
          // Add new cycle
          updateOp = { 
            $push: { workflowCycles: cycleCopy }
          };
          console.log(`[DEBUG] Adding new cycle to workflowCycles array`);
        }
        
        // Apply the update
        await ArtifactModel.findByIdAndUpdate(
          freshArtifact._id,
          updateOp,
          { new: false }  // Don't need the updated document right now
        );
      }
      
      // Now initialize a new workflow cycle - this will handle the updates atomically
      return await ArtifactWorkflowController._initializeWorkflowCycle(freshArtifact._id);
    } else {
      console.log(`[INFO] WORKFLOW COMPLETED - No tickets returned or vulnerabilities remaining`);
      
      // Update workflow completed status - use only one atomic operation
      const completedArtifact = await ArtifactModel.findByIdAndUpdate(
        artifact._id,
        { $set: { workflowCompleted: true } },
        { new: true }
      );
      
      return completedArtifact;
    }
  }

  private static async _getTicketCounts(artifactId: string | mongoose.Types.ObjectId): Promise<{
    tickets: any[];
    assigned: any[];
    unassigned: any[];
    submitted: any[];
    notSubmitted: any[];
    resolved: any[];
    returned: any[];
  }> {
    
    // Get the artifact with populated threatList
    const artifact = await ArtifactModel.findById(artifactId).populate('threatList');
    
    if (!artifact || !artifact.threatList) {
      return {
        tickets: [],
        assigned: [],
        unassigned: [],
        submitted: [],
        notSubmitted: [],
        resolved: [],
        returned: []
      };
    }
    
    // Get threat IDs
    const threatIds = artifact.threatList.map((threat: any) => threat._id);
    
    // Query tickets for these threats
    const tickets = await TicketModel.find({ 
      targetedThreat: { $in: threatIds }
    });
        
    // Categorize tickets
    const assigned = tickets.filter((ticket: any) => ticket.status !== "Not accepted");
    const unassigned = tickets.filter((ticket: any) => ticket.status === "Not accepted");
    
    const submitted = tickets.filter((ticket: any) => 
      ticket.status === "Submitted" || ticket.status === "Resolved"
    );
    
    const notSubmitted = tickets.filter((ticket: any) => 
      ticket.status !== "Submitted" && ticket.status !== "Resolved"
    );
    
    const resolved = tickets.filter((ticket: any) => ticket.status === "Resolved");
    
    // Identify returned tickets using previousStatus field
    // A ticket is considered returned if it was in "Submitted" status but now back in "Processing"
    const returned = tickets.filter((ticket: any) => 
      ticket.status === "Processing" && ticket.previousStatus === "Submitted"
    );
    
    return {
      tickets,
      assigned,
      unassigned,
      submitted,
      notSubmitted,
      resolved,
      returned
    };
  }

  private static _syncWorkflowCycles(artifact: any): void {
    console.log(`[DEBUG] Syncing workflow cycles for artifact: ${artifact._id}`);
    
    if (!artifact.currentWorkflowCycle) {
      console.log(`[WARN] No currentWorkflowCycle to sync`);
      return;
    }
    
    if (!artifact.workflowCycles) {
      console.log(`[DEBUG] workflowCycles array not found, initializing empty array`);
      artifact.workflowCycles = [];
    }
    
    const currentCycleNumber = artifact.currentWorkflowCycle.cycleNumber;
    console.log(`[DEBUG] Syncing cycle #${currentCycleNumber}`);
    
    // Find the matching cycle in the workflowCycles array
    const cycleIndex = artifact.workflowCycles.findIndex(
      (cycle: any) => cycle.cycleNumber === currentCycleNumber
    );
    
    // Create deep copy to ensure it's a separate object
    const cycleCopy = JSON.parse(JSON.stringify(artifact.currentWorkflowCycle));
    
    if (cycleIndex === -1) {
      // Add it if not found
      console.log(`[DEBUG] Cycle #${currentCycleNumber} not found in workflowCycles array, adding it`);
      artifact.workflowCycles.push(cycleCopy);
    } else {
      // Replace the existing cycle with the current one to ensure they're in sync
      console.log(`[DEBUG] Updating existing cycle #${currentCycleNumber} at index ${cycleIndex}`);
      artifact.workflowCycles[cycleIndex] = cycleCopy;
    }
    
    // Ensure workflowCyclesCount is consistent with the current cycle
    if ((artifact.workflowCyclesCount || 0) < currentCycleNumber) {
      console.log(`[DEBUG] Updating workflowCyclesCount from ${artifact.workflowCyclesCount} to ${currentCycleNumber}`);
      artifact.workflowCyclesCount = currentCycleNumber;
    }
  }
  private static _validateWorkflowConsistency(artifact: any): void {
    console.log(`[DEBUG] Validating workflow consistency for artifact: ${artifact._id}`);
    
    if (!artifact.currentWorkflowCycle) {
      console.log(`[WARN] No currentWorkflowCycle to validate`);
      return;
    }
    
    if (!artifact.workflowCycles || artifact.workflowCycles.length === 0) {
      console.log(`[WARN] workflowCycles array is empty or undefined`);
      return;
    }
    
    const currentCycleNumber = artifact.currentWorkflowCycle.cycleNumber;
    const matchingCycle = artifact.workflowCycles.find((c: any) => c.cycleNumber === currentCycleNumber);
    
    if (!matchingCycle) {
      console.log(`[ERROR] Current cycle #${currentCycleNumber} not found in workflowCycles array!`);
      console.log(`[DEBUG] Available cycles:`, artifact.workflowCycles.map((c: any) => c.cycleNumber));
      
      // Auto-fix: add the current cycle to the array
      console.log(`[INFO] Auto-fixing: Adding current cycle to workflowCycles array`);
      const cycleCopy = JSON.parse(JSON.stringify(artifact.currentWorkflowCycle));
      artifact.workflowCycles.push(cycleCopy);
    } else {
      // Verify that the steps match
      if (matchingCycle.currentStep !== artifact.currentWorkflowCycle.currentStep) {
        console.log(`[WARN] Step mismatch: currentWorkflowCycle.currentStep=${artifact.currentWorkflowCycle.currentStep}, workflowCycles[].currentStep=${matchingCycle.currentStep}`);
        
        // Auto-fix: update the cycle in the array
        const index = artifact.workflowCycles.findIndex((c: any) => c.cycleNumber === currentCycleNumber);
        if (index !== -1) {
          console.log(`[INFO] Auto-fixing: Updating cycle in workflowCycles array`);
          artifact.workflowCycles[index] = JSON.parse(JSON.stringify(artifact.currentWorkflowCycle));
        }
      }
    }
    
    // Ensure workflowCyclesCount is consistent
    if (artifact.workflowCyclesCount !== currentCycleNumber) {
      console.log(`[WARN] workflowCyclesCount (${artifact.workflowCyclesCount}) does not match currentWorkflowCycle.cycleNumber (${currentCycleNumber})`);
      console.log(`[INFO] Auto-fixing: Setting workflowCyclesCount to ${currentCycleNumber}`);
      artifact.workflowCyclesCount = currentCycleNumber;
    }
  }
}
