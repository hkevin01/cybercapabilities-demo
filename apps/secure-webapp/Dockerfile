FROM node:20-slim

# Install wget for health checks
RUN apt-get update && apt-get install -y wget && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install --only=production

# Copy app
COPY src/ ./src/

# Create non-root user  
RUN groupadd -r nodeapp && useradd -r -g nodeapp nodeapp
RUN chown -R nodeapp:nodeapp /app
USER nodeapp

EXPOSE 3001

CMD ["node", "src/app-final.js"]
