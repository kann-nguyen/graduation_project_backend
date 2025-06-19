/**
 * ESM-compatible Octokit loader for CommonJS environments
 * This file is explicitly JavaScript (not TypeScript) to avoid transpilation issues
 */

// This file will be copied as-is to dist, not transpiled
async function createOctokitClient(auth) {
  try {
    // Use dynamic imports to load ESM modules in CommonJS environment
    const { Octokit } = await import('@octokit/core');
    const { paginateRest } = await import('@octokit/plugin-paginate-rest');
    const { restEndpointMethods } = await import('@octokit/plugin-rest-endpoint-methods');
    
    // Create Octokit class with plugins
    const MyOctokit = Octokit.plugin(paginateRest, restEndpointMethods);
    
    // Return a new instance with authentication
    return new MyOctokit({ auth: auth || '' });
  } catch (error) {
    console.error('Failed to create Octokit client:', error);
    throw error;
  }
}

module.exports = { createOctokitClient };
