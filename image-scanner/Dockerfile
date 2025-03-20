FROM node:latest

WORKDIR /app

RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

COPY package.json ./

ADD . ./
RUN npm install

EXPOSE 3000

# Start the API
CMD [ "npm", "run", "start" ]