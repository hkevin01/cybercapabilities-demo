FROM node:20-slim

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy app
COPY src/ ./src/

# Create non-root user  
RUN groupadd -r nodeapp && useradd -r -g nodeapp nodeapp
RUN chown -R nodeapp:nodeapp /app
USER nodeapp

EXPOSE 3001

CMD ["node", "src/app-final.js"]
