FROM node:lts-alpine

WORKDIR /app
COPY package*.json ./

RUN npm install

RUN npm install --only=production

ARG PORT

EXPOSE ${PORT}

CMD [ "npm", "start" ]

