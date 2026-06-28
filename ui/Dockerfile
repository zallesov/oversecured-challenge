FROM node:22-alpine AS build

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
