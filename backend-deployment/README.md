# Backend Deployment README

# Project Overview
This project is a Node.js/Express application packaged as a Docker container. It includes a Docker setup for building and deploying the application on an Ubuntu VM server. The application is designed to run on one of the specified ports from 6800 to 6899.

# Project Structure
The project has the following structure:

```
backend-deployment
├── .dockerignore
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── nginx
│   └── nginx.conf
├── scripts
│   ├── build.sh
│   └── deploy.sh
└── README.md
```

# Getting Started

## Prerequisites
- Docker installed on your local machine and the Ubuntu VM server.
- Docker Compose installed.
- Node.js and npm installed (for local development).

## Setup Instructions

1. **Clone the Repository**
   Clone the repository to your local machine.

   ```
   git clone <repository-url>
   cd backend-deployment
   ```

2. **Configure Environment Variables**
   Copy the `.env.example` file to `.env` and fill in the required environment variables.

   ```
   cp .env.example .env
   ```

3. **Build the Docker Image**
   Run the build script to create the Docker image.

   ```
   ./scripts/build.sh
   ```

4. **Run the Application**
   Use Docker Compose to start the application. Make sure to specify the port you want to use (between 6800 and 6899) in the `docker-compose.yml` file.

   ```
   docker-compose up
   ```

## Deployment Instructions

1. **Deploy to Ubuntu VM**
   Use the deploy script to automate the deployment process.

   ```
   ./scripts/deploy.sh
   ```

## Nginx Configuration
The Nginx configuration file is located in the `nginx` directory. It is set up to route requests to the Node.js application. Ensure that the upstream server configuration matches the Docker container settings.

## Additional Information
For more details on each file and its purpose, refer to the comments within the respective files. This project is designed to be easily extensible and maintainable, allowing for future enhancements and features.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.