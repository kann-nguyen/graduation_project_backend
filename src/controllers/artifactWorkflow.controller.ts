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

  private static async _initializeWorkflowCycle(artifactId: string | mongoose.Types.ObjectId) {    const artifact = await ArtifactModel.findById(artifactId);
    if (!artifact) {
      throw new Error('Artifact not found');
    }

    // Create a new workflow cycle
    const cycleNumber = (artifact.workflowCyclesCount || 0) + 1;
    const newCycle = {
      cycleNumber,
      currentStep: 1, // Start at step 1 (Detection)
      startedAt: new Date(),
      // Initialize all steps to ensure they exist in both currentWorkflowCycle and workflowCycles array
      detection: {
        completedAt: new Date(), // Detection is completed when the cycle starts
        numberVuls: 0,
        listVuls: []
      },
      classification: {
        numberThreats: 0,
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
    };// Initialize or update the artifact's workflow properties
    artifact.workflowCyclesCount = cycleNumber - 1; // Will be incremented to cycleNumber when completed
    artifact.currentWorkflowStep = 1;
    artifact.workflowCompleted = false;    // Set the current workflow cycle
    artifact.currentWorkflowCycle = newCycle;
    
    // Make sure workflowCycles array exists
    if (!artifact.workflowCycles) {
      artifact.workflowCycles = [];
    }
    
    // Create a separate deep clone of the cycle to ensure it's properly added to array
    // This avoids reference issues where changes to current cycle might not reflect in array
    const deepCopy = JSON.parse(JSON.stringify(newCycle));
    
    // Add to workflow cycles as a plain object - Mongoose will handle conversion
    artifact.workflowCycles.push(deepCopy);
    
    // Validate that data is consistent 
    const lastCycleInArray = artifact.workflowCycles[artifact.workflowCycles.length - 1];
    
    await artifact.save();
    return artifact;
  }

  private static async _startNewWorkflowCycle(artifactId: string | mongoose.Types.ObjectId) {
    const artifact = await ArtifactModel.findById(artifactId);
    if (!artifact) {
      throw new Error('Artifact not found');
    }

    // Check if current cycle is complete
    if (!artifact.currentWorkflowCycle?.completedAt) {
      throw new Error('Cannot start a new cycle before completing the current one');
    }
    return await this._initializeWorkflowCycle(artifactId);
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
      // Mark the current cycle as completed
      if (artifact.currentWorkflowCycle) {
        artifact.currentWorkflowCycle.completedAt = new Date();
      }      // Increment the workflow cycles count
      artifact.workflowCyclesCount = (artifact.workflowCyclesCount || 0) + 1;
      
      // Reset step to 1 for potential next cycle
      nextStep = 1;
      artifact.workflowCompleted = true;
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
    if (artifact.isScanning) {
      return artifact;
    }
      // Get ticket counts and lists using our utility method
    const {
      tickets,
      resolved: resolvedTickets,
      returned: returnedTickets    } = await ArtifactWorkflowController._getTicketCounts(artifact._id);
    
    
    // Update verification step data
    if (artifact.currentWorkflowCycle) {
      if (!artifact.currentWorkflowCycle.verification) {
        artifact.currentWorkflowCycle.verification = {};
      }
      
      artifact.currentWorkflowCycle.verification.numberTicketsResolved = resolvedTickets.length;
      artifact.currentWorkflowCycle.verification.numberTicketsReturnedToProcessing = returnedTickets.length;
      artifact.currentWorkflowCycle.verification.completedAt = new Date();
      
      // Mark as successful if all submitted tickets were resolved
      artifact.currentWorkflowCycle.verification.success = returnedTickets.length === 0;
      artifact.currentWorkflowCycle.verification.notes = returnedTickets.length === 0 
        ? "All issues verified successfully" 
        : `${returnedTickets.length} tickets returned for further remediation`;
      
      await artifact.save();
    }
    
    // Complete this workflow cycle and potentially start a new one
    
    // Check if any issues require another cycle
    if (returnedTickets.length > 0 || artifact.vulnerabilityList?.length > 0) {
      return await ArtifactWorkflowController._startNewWorkflowCycle(artifact._id);
    } else {
      artifact.workflowCompleted = true;
      await artifact.save();
      return artifact;
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
    
    // For returned tickets, we need to check history notes or assume based on workflow context
    // Here we'll use a simple heuristic that if a ticket was in Processing after being in Submitted,
    // it was likely returned
    const returned = tickets.filter((ticket: any) => 
      ticket.status === "Processing" && ticket.historyNotes?.some((note: string) => 
        note.includes("returned") || note.includes("reverted")
      )
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
    
    if (!artifact.currentWorkflowCycle) {
      return;
    }
    
    if (!artifact.workflowCycles) {
      artifact.workflowCycles = [];
    }
    
    const currentCycleNumber = artifact.currentWorkflowCycle.cycleNumber;
    
    // Find the matching cycle in the workflowCycles array
    const cycleIndex = artifact.workflowCycles.findIndex(
      (cycle: any) => cycle.cycleNumber === currentCycleNumber
    );
    
    if (cycleIndex === -1) {
      // Create deep copy to ensure it's a separate object
      const cycleCopy = JSON.parse(JSON.stringify(artifact.currentWorkflowCycle));
      
      // Add it if not found
      artifact.workflowCycles.push(cycleCopy);
      return;
    }
    
    // Create deep copy to ensure it's a separate object
    const cycleCopy = JSON.parse(JSON.stringify(artifact.currentWorkflowCycle));
    
    // Replace the existing cycle with the current one to ensure they're in sync
    artifact.workflowCycles[cycleIndex] = cycleCopy;
  }

  private static _validateWorkflowConsistency(artifact: any): void {
    if (!artifact.currentWorkflowCycle) {
      return;
    }
    
    if (!artifact.workflowCycles || artifact.workflowCycles.length === 0) {
      return;
    }
    
    const currentCycleNumber = artifact.currentWorkflowCycle.cycleNumber;
    const matchingCycle = artifact.workflowCycles.find((c: any) => c.cycleNumber === currentCycleNumber);
    
    if (!matchingCycle) {
      return;
    }
  }
}
