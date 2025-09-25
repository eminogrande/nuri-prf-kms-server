FROM node:20-alpine
RUN apk add --no-cache python3 make g++ py3-pip
WORKDIR /app
COPY package*.json ./
COPY server-prf-kms/ ./server-prf-kms/
RUN npm install --omit=optional
EXPOSE 1337
CMD ["node", "server-prf-kms/server-prf-kms.js"]