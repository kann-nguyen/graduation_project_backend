# Use the latest Node.js image
FROM node:latest

# Set the working directory
WORKDIR /app

# Install necessary SSL libraries and tools
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Grype for security scanning
RUN wget -qO- https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Trivy for security scanning
RUN wget -qO- https://github.com/aquasecurity/trivy/releases/download/v0.21.0/trivy_0.21.0_Linux-64bit.tar.gz | tar xz && \
    mv trivy /usr/local/bin/

# Install Cosign for signature verification
RUN wget -qO cosign-linux-amd64 https://github.com/sigstore/cosign/releases/download/v1.10.0/cosign-linux-amd64 && \
    mv cosign-linux-amd64 /usr/local/bin/cosign && \
    chmod +x /usr/local/bin/cosign

# Install Kube-bench for Kubernetes security checks
RUN wget -qO- https://github.com/aquasecurity/kube-bench/releases/download/v0.6.6/kube-bench_0.6.6_Linux_amd64.tar.gz | tar xz && \
    mv kube-bench /usr/local/bin/

# Copy package.json and install dependencies
COPY package.json package-lock.json ./
RUN npm install --production

# Copy the rest of the application code
COPY . .

# Expose port 5000 for API
EXPOSE 6000

# Start the application
CMD ["npm", "run", "start"]
