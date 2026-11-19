# Exorcist 98 web app as a self-contained Node server.
#   docker build -t exorcist-98 .
#   docker run -p 3000:3000 exorcist-98
# No git binary, no cloud credentials and no AI service are needed: GitHub
# repositories are fetched as tarballs over HTTPS.

FROM node:22-slim AS build
WORKDIR /app
COPY . .
RUN npm install --global --no-fund --no-audit "$(node -p "require('./package.json').packageManager")" \
 && pnpm install --frozen-lockfile --filter "@exorcist-98/web..." \
 && NEXT_TELEMETRY_DISABLED=1 pnpm --filter @exorcist-98/web build

FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production PORT=3000 HOSTNAME=0.0.0.0 NEXT_TELEMETRY_DISABLED=1
# The standalone output already contains definitions/ and fixtures/haunted-repo/.
COPY --from=build /app/apps/web/.next/standalone ./
COPY --from=build /app/apps/web/.next/static ./apps/web/.next/static
USER node
EXPOSE 3000
CMD ["node", "apps/web/server.js"]
