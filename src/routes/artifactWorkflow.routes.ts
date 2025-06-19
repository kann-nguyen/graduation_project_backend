import express from 'express';
import { ArtifactWorkflowController } from '../controllers/artifactWorkflow.controller';
import { checkAuth } from '../middlewares/auth';

const router = express.Router();

// All routes in this router need authentication
//router.use(checkAuth);
// Get workflow history for an artifact
router.get('/artifacts/:artifactId/workflow/history', ArtifactWorkflowController.getWorkflowHistory);

// Get workflow statistics for a project
// We don't use route params for the project name because it may contain slashes
// Instead, we'll extract it manually from the full URL in the controller
router.get('/projects/**/workflow/stats', ArtifactWorkflowController.getProjectWorkflowStats);

// Get artifacts by workflow step
// We don't use route params for the project name because it may contain slashes
// Instead, we'll extract it manually from the full URL in the controller
router.get('/projects/**/workflow/artifacts', ArtifactWorkflowController.getArtifactsByWorkflowStep);

export default router;
