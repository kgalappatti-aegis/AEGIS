# Build context: ./aegis-ui

# ── Build stage ────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build


# ── Runtime stage (nginx) ──────────────────────────────────────────────────
FROM nginx:1.27-alpine

COPY --from=builder /app/dist /usr/share/nginx/html

# Minimal nginx config: serve SPA, proxy /ws → bridge, /api → frontend
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
