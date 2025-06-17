import express from 'express';
import { ArtifactWorkflowController } from '../controllers/artifactWorkflow.controller';
import { checkAuth } from '../middlewares/auth';

const router = express.Router();

// All routes in this router need authentication
router.use(checkAuth);
// Get workflow history for an artifact
router.get('/artifacts/:artifactId/workflow/history', ArtifactWorkflowController.getWorkflowHistory);

// Get workflow statistics for a project
router.get('/projects/:projectId/workflow/stats', ArtifactWorkflowController.getProjectWorkflowStats);

// Get artifacts by workflow step
router.get('/projects/:projectId/workflow/artifacts', ArtifactWorkflowController.getArtifactsByWorkflowStep);

export default router;
