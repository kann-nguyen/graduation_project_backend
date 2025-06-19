FROM node:18

WORKDIR /app

# Install build dependencies for native modules like bcrypt
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*

# Copy package files and install dependencies
COPY package.json package-lock.json ./
RUN npm ci

# Copy all project files
COPY . .

# Build project
RUN npm run build

# Make sure JSON files are copied to dist
RUN mkdir -p dist/utils && \
    cp -r src/utils/*.json dist/utils/ && \
    ls -la dist/utils/ && \
    ls -la src/utils/

# Expose the correct port
EXPOSE 6800

# Start application
CMD ["node", "dist/server.js"]