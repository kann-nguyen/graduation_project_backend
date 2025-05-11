import { Artifact } from '../models/artifact';
import { exec } from 'child_process';
import { promisify } from 'util';

const execPromise = promisify(exec);

/**
 * Validates artifact data before adding it to a phase
 * @param data Artifact data from request
 * @returns Object with validation result and error message if applicable
 */
export async function validateArtifact(data: any): Promise<{ valid: boolean; error?: string }> {
    const { name, version, type, url } = data;

    // Basic validation
    if (!name || !type) {
        return { valid: false, error: "Missing required fields: name or type" };
    }

    try {
        // Validate based on artifact type
        switch (type) {
            case "image":
                // For Docker images, we need name, version and url
                if (!version) {
                    return { valid: false, error: "Missing required field: version for Docker image" };
                }
                if (!url) {
                    return { valid: false, error: "Missing required field: url for Docker image" };
                }

                let imageName = "";
                let imageTag = "";
                let pullImage = url;

                // Check if URL is a Docker Hub URL
                if (url.includes("hub.docker.com")) {
                    console.log("[INFO] Validating Docker Hub URL");

                    // Extract information from Docker Hub URL
                    // Example: https://hub.docker.com/layers/library/alpine/3.15/images/sha256-4cc0f70de3f6a3ba950408acaf585230acf2405e71d29a46c50feef9117d693d

                    // Split URL to extract name and version
                    const urlParts = url.split('/');

                    // Check for library-specific URLs
                    const libraryIndex = urlParts.indexOf("library");
                    if (libraryIndex > -1 && libraryIndex + 2 < urlParts.length) {
                        // For official images: library/name/tag
                        imageName = urlParts[libraryIndex + 1];
                        imageTag = urlParts[libraryIndex + 2];
                        pullImage = `${imageName}:${imageTag}`;
                    } else if (url.includes("/layers/")) {
                        // For normal layers URLs: layers/image/tag or layers/namespace/image/tag
                        const layersIndex = urlParts.indexOf("layers");
                        if (layersIndex > -1) {
                            // Find the 'images' segment to determine where the tag is
                            const imagesIndex = urlParts.indexOf("images");

                            if (imagesIndex > layersIndex + 2) {
                                // Check if there's a namespace/image pattern (like vulnerables/web-dvwa)
                                if (imagesIndex - layersIndex > 3) {
                                    // Format: layers/namespace/image/tag/images
                                    // Construct a full repository name including namespace
                                    const namespace = urlParts[layersIndex + 1];
                                    const repositoryName = urlParts[layersIndex + 2];
                                    imageName = `${namespace}/${repositoryName}`;
                                    imageTag = urlParts[layersIndex + 3];
                                } else {
                                    // Format: layers/image/tag/images
                                    imageName = urlParts[layersIndex + 1];
                                    imageTag = urlParts[layersIndex + 2];
                                }
                                pullImage = `${imageName}:${imageTag}`;
                                console.log(`[INFO] Found layers pattern with images marker: ${pullImage}`);
                            } else if (layersIndex + 3 < urlParts.length) {
                                // Basic pattern without 'images' segment
                                // Check if this is a namespace/image pattern
                                const remainingParts = urlParts.slice(layersIndex + 1);

                                if (remainingParts.length >= 3) {
                                    // This is likely a namespace/image/tag format
                                    imageName = `${remainingParts[0]}/${remainingParts[1]}`;
                                    imageTag = remainingParts[2];
                                } else {
                                    // Simple image/tag format
                                    imageName = remainingParts[0];
                                    imageTag = remainingParts[1];
                                }
                                pullImage = `${imageName}:${imageTag}`;
                            }
                        }
                    } else if (url.includes("/r/")) {
                        // For repository URLs: r/username/repo
                        const rIndex = urlParts.indexOf("r");
                        if (rIndex > -1 && rIndex + 1 < urlParts.length) {
                            const repoPath = urlParts[rIndex + 1];

                            // Check if there's a tag specified in the URL
                            if (rIndex + 2 < urlParts.length && urlParts[rIndex + 2] !== "tags") {
                                imageTag = urlParts[rIndex + 2];
                            } else {
                                imageTag = version; // Default to provided version
                            }

                            imageName = repoPath;
                            pullImage = `${imageName}:${imageTag}`;
                        }
                    }

                    console.log(`[INFO] Extracted from Docker Hub - Name: ${imageName}, Tag: ${imageTag}, Pull image: ${pullImage}`);

                    // If we couldn't extract the information, return an error
                    if (!imageName || !imageTag) {
                        return {
                            valid: false,
                            error: "Could not extract image name and tag from Docker Hub URL"
                        };
                    }
                } else {
                    // Handle normal Docker image references like "alpine:3.15"
                    const imageRegex = /^(?:([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*(?::[0-9]+)?)\/)?((?:[a-z0-9]+(?:[._-][a-z0-9]+)*\/)*[a-z0-9]+(?:[._-][a-z0-9]+)*)(?::([\w][\w.-]{0,127}))?$/;

                    if (!imageRegex.test(url)) {
                        return {
                            valid: false,
                            error: "Invalid Docker image URL format. Expected either a Docker Hub URL or a direct image reference"
                        };
                    }

                    // Extract the image name and tag from URL
                    const parts = url.split(":");
                    if (parts.length > 1) {
                        imageTag = parts[parts.length - 1];
                        imageName = parts.slice(0, parts.length - 1).join(":");
                    } else {
                        imageName = url;
                        imageTag = "latest";
                    }

                    // Get the name without registry and path
                    imageName = imageName.split("/").pop() || "";
                }
                // Check if the extracted name matches the provided name
                if (imageName && imageName !== name) {
                    // Special check for when imageName contains slashes (e.g., 'vulnerables/web-dvwa')
                    // and the provided name is just one part (e.g., 'web-dvwa' or 'vulnerables')
                    const imageNameParts = imageName.split('/');
                    const lastPart = imageNameParts[imageNameParts.length - 1];

                    // If neither the full name nor the last part matches, it's a mismatch
                    if (imageNameParts.length > 1 && (lastPart === name || imageNameParts[0] === name)) {
                        console.log(`[INFO] Partial match accepted: ${name} is part of ${imageName}`);
                    } else {
                        return {
                            valid: false,
                            error: `Docker image name mismatch: provided name "${name}" doesn't match image name "${imageName}"`
                        };
                    }                }
                // Check if the extracted tag matches the provided version
                if (imageTag && imageTag !== version) {
                    return {
                        valid: false,
                        error: `Docker image version mismatch: provided version "${version}" doesn't match image tag "${imageTag}"`
                    };
                }
                
                // Validate that the Docker image exists (attempt to pull it)
                try {
                    console.log(`[INFO] Validating Docker image existence: ${pullImage}`);
                    // Try to pull the image to check if it exists
                    await execPromise(`docker pull ${pullImage} --quiet`);
                    console.log(`[INFO] Docker image validation successful: ${pullImage}`);
                    
                    // Clean up the pulled image to save disk space
                    try {
                        console.log(`[INFO] Removing Docker image after validation: ${pullImage}`);
                        await execPromise(`docker rmi ${pullImage} --force`);
                        console.log(`[INFO] Successfully removed Docker image: ${pullImage}`);
                    } catch (rmError: any) {
                        // Log the error but don't fail validation if cleanup fails
                        console.warn(`[WARN] Failed to remove Docker image after validation: ${rmError.message || 'Unknown error'}`);
                    }
                } catch (error: any) {
                    console.error("[ERROR] Docker image validation failed:", error);
                    return {
                        valid: false,
                        error: `Failed to validate Docker image: ${error.message || 'Unknown error'}. Make sure the image exists and is accessible.`
                    };
                }
                break;

            case "source code":
                // Source code validation
                if (!url) {
                    return { valid: false, error: "Missing required field: url for source code" };
                }

                // Validate URL is a valid Git repository or source code archive
                const validSourcePattern = /^(https?:\/\/|git@).*\.(git|zip)$/i;
                const isGitPlatform = /^https?:\/\/(github\.com|gitlab\.com|bitbucket\.org)/i.test(url);

                if (!validSourcePattern.test(url) && !isGitPlatform) {
                    return { valid: false, error: "URL does not appear to be a valid Git repository or ZIP archive" };
                }
                break;

            case "docs":
                // Document validation
                if (!url) {
                    return { valid: false, error: "Missing required field: url for document" };
                }

                // Check if the URL points to a document file
                const documentExtensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.md'];
                const hasValidExtension = documentExtensions.some(ext => url.toLowerCase().endsWith(ext));

                if (!hasValidExtension) {
                    return { valid: false, error: "URL does not point to a supported document type" };
                }
                break;

            default:
                // For other types, basic validation is sufficient
                break;
        }

        return { valid: true };
    } catch (error: any) {
        console.error("[ERROR] Artifact validation failed:", error);
        return { valid: false, error: `Validation error: ${error.message || 'Unknown error'}` };
    }
}
