FROM node:22-alpine AS build

# VITE_POCKETBASE_URL is the browser-reachable PocketBase URL, baked into the client
# bundle at build time. Pass via `docker build --build-arg VITE_POCKETBASE_URL=...`
# or the `args:` block in docker-compose.
ARG VITE_POCKETBASE_URL
ENV VITE_POCKETBASE_URL=$VITE_POCKETBASE_URL

WORKDIR /app/ui

COPY ui/package*.json ./
RUN npm install

COPY ui/ ./
RUN npm run build

FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app/ui

COPY ui/package*.json ./
RUN npm install --omit=dev

COPY --from=build /app/ui/dist ./dist

EXPOSE 3000

CMD ["node", "dist/server/index.js"]
