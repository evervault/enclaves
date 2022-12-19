FROM node:16-alpine

COPY index.mjs /index.mjs
COPY package.json /package.json
COPY package-lock.json /package-lock.json

RUN npm ci

EXPOSE 3000

ENTRYPOINT ["npm", "start"]