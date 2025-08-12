FROM node:20-alpine

# Install wget for health checks
RUN apk add --no-cache wget

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci || npm install
COPY src ./src
EXPOSE 3000
CMD ["npm", "start"]
