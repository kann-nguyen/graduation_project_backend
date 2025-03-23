# Use official Node.js image
FROM node:18

# Set working directory
WORKDIR /app

# Copy package.json and install dependencies
COPY package.json package-lock.json ./
RUN npm install

# Copy all project files
COPY . .

# Build project (nếu cần)
RUN npm run build

# Expose port (nếu cần, ví dụ: 3000)
EXPOSE 3001

# Start application
CMD ["npm", "start"]
