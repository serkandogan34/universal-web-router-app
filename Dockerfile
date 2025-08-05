FROM node:18-alpine

RUN apk add --no-cache curl

WORKDIR /app

COPY package.json .
COPY package-lock.json .
RUN npm install
COPY index.js .

EXPOSE 3000
CMD ["npm", "start"]
