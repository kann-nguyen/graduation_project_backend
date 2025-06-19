#!/bin/bash

# Set the environment variables
export $(cat ../.env | xargs)

# Define the Docker image name and container name
IMAGE_NAME="your-image-name"  # Replace with your actual image name
CONTAINER_NAME="your-container-name"  # Replace with your actual container name
PORT=6800  # Replace with the desired port from 6800 to 6899

# Pull the latest image
docker pull $IMAGE_NAME

# Stop and remove the existing container if it exists
if [ $(docker ps -q -f name=$CONTAINER_NAME) ]; then
    docker stop $CONTAINER_NAME
    docker rm $CONTAINER_NAME
fi

# Run the new container
docker run -d \
    --name $CONTAINER_NAME \
    -p $PORT:3000 \  # Assuming your app runs on port 3000 inside the container
    --env-file ../.env \
    $IMAGE_NAME

echo "Deployment completed. The application is running on port $PORT."