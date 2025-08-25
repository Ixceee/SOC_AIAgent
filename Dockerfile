FROM node:18

WORKDIR /app

# Copy package.json FIRST (best practice for caching)
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the files
COPY . .

# Your remaining commands (e.g., CMD)
CMD ["npm", "start"]