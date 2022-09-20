FROM node:16-alpine

COPY index.mjs /index.mjs
COPY package.json /package.json
COPY package-lock.json /package-lock.json

RUN npm ci

ARG API_KEY
ENV EV_API_KEY=${API_KEY}
EXPOSE 3000

ENTRYPOINT ["npm", "start"]