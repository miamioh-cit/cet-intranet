FROM node:24-alpine AS auth-dependencies
WORKDIR /app/auth
COPY auth/package.json auth/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY auth/server.cjs auth/account-store.cjs auth/server.test.cjs ./
RUN npm test && rm server.test.cjs

FROM nginx:alpine
RUN apk add --no-cache nodejs
COPY --from=auth-dependencies /app/auth /app/auth
COPY default.conf /etc/nginx/conf.d/default.conf
WORKDIR /usr/share/nginx/html
COPY index.html advising.html styles.css theme.js portal.js ./
COPY images/ ./images/
COPY admin/ ./admin/
COPY login/ ./login/

