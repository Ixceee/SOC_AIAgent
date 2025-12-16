# Use official Node.js runtime
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (including csv-parser)
RUN npm install

# Copy source code
COPY . .

# Create scripts directory if it doesn't exist
RUN mkdir -p scripts

# Copy script files
COPY scripts/ ./scripts/

# Copy threat intelligence data files
COPY blacklist.txt ./
COPY GeoLite2-ASN-Blocks-IPv4.csv ./
COPY GeoLite2-ASN-Blocks-IPv6.csv ./
COPY GeoLite2-Country.mmdb ./

# Expose port
EXPOSE 11435

# Start the application
CMD ["node", "server.js"]