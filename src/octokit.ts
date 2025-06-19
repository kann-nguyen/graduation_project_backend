/**
 * This module provides a wrapper for Octokit that handles the ESM/CommonJS compatibility issue.
 * We use a special JS file for ESM loading to avoid TypeScript compilation issues.
 */

// Import the loader function (will be directly used in production)
// In dev, this will be loaded by TypeScript
// In prod, this will be a direct require of the copied JS file
import { createOctokitClient as loader } from './utils/octokit-esm-loader';

/**
 * Create an Octokit client with the provided authentication token
 * 
 * @param auth - Authentication token (optional)
 * @returns A Promise that resolves to an authenticated Octokit instance
 */
export async function createOctokitClient(auth?: string) {
  try {
    return await loader(auth);
  } catch (error) {
    console.error('Failed to create Octokit client:', error);
    throw error;
  }
}

// For backward compatibility with existing code
export default createOctokitClient;
