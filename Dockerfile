FROM node:20-alpine
RUN apk add --no-cache python3 make g++ py3-pip

WORKDIR /app

# Install dependencies for the signer only
COPY server-prf-kms/package.json server-prf-kms/package-lock.json ./server-prf-kms/
RUN npm ci --omit=optional --prefix server-prf-kms

# Copy application source
COPY server-prf-kms/ ./server-prf-kms/

EXPOSE 1337
CMD ["node", "server-prf-kms/server-prf-kms.js"]
