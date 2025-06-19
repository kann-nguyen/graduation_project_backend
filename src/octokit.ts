// Create a singleton instance of the Octokit class for reuse
let OctokitSingleton: any = null;

// Create a function that will initialize the Octokit instance
async function createOctokit() {
  // Use dynamic imports for ESM modules
  const { Octokit } = await import("@octokit/core");
  const { paginateRest } = await import("@octokit/plugin-paginate-rest");
  const { restEndpointMethods } = await import("@octokit/plugin-rest-endpoint-methods");

  return Octokit.plugin(paginateRest, restEndpointMethods);
}

// Export the function that creates and returns a configured Octokit instance
export default async function getOctokit() {
  if (!OctokitSingleton) {
    OctokitSingleton = await createOctokit();
  }
  return OctokitSingleton;
}

// Convenience function to create an authenticated client
export async function createOctokitClient(auth: string) {
  const OctokitClass = await getOctokit();
  return new OctokitClass({ auth });
}
