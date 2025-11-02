# Campus Cart Lite - container image
FROM node:20-alpine

WORKDIR /app

# Install deps
COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --prod

# Copy source
COPY . .

ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080

# Allow overriding data directory in hosts
# e.g., set DATA_DIR=/data and mount a volume at /data
CMD ["node", "server.js"]
