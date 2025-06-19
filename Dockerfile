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

# Make sure JSON files and JS files are copied to dist
RUN mkdir -p dist/utils && \
    cp -r src/utils/*.json dist/utils/ && \
    cp src/utils/octokit-esm-loader.js dist/utils/ && \
    ls -la dist/utils/ && \
    ls -la src/utils/ && \
    echo "Content of dist folder:" && \
    find dist -type f | sort&& \
    echo "Content of dist folder:" && \
    find dist -type f | sort

# Expose the correct port
EXPOSE 6800

# Start application
CMD ["node", "dist/server.js"]