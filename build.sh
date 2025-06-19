#!/bin/bash

# Navigate to the backend-deployment directory
# cd "$(dirname "$0")/.."

# Build the Docker image
docker build -t nguyen-van-tan .

# Optionally, you can tag the image with a version
docker tag nguyen-van-tan nguyen-van-tan:latest

# Print a success message
echo "Docker image built successfully!"