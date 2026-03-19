FROM node:lts-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --production

COPY . .

CMD ["node", "index.js", "--transport", "http"]
