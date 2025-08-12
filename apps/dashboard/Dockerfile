FROM node:18-alpine

# Install wget for health checks
RUN apk add --no-cache wget

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --only=production

# Copy application code
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S dashboard -u 1001

# Change ownership
RUN chown -R dashboard:nodejs /app
USER dashboard

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget -q -O- http://localhost:8080/health || exit 1

EXPOSE 8080 8081

CMD ["npm", "start"]
