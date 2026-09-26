FROM node:24-alpine

WORKDIR /app

# Runtime deps only (jose). The .ts files run directly via Node type stripping,
# so no build step and no TypeScript at runtime.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src

# Overridden per service in the compose files.
CMD ["node", "src/cloud/main.ts"]
