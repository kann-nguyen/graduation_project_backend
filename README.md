# Install

1. Install latest version of [Node.js](https://nodejs.org/en/download)
2. Install [pnpm](https://pnpm.io/installation)
3. Run `pnpm install` to install dependencies
4. Run `npm run dev` to run the API server

# Enabling image scanning for artifacts

1. Install [Docker](https://docs.docker.com/get-docker/)
2. Install [ngrok](https://ngrok.com/download)
3. Run `cd image-scanner`
4. Run `docker-compose up -d`
5. Now the web service is running on port 3000. Expose it to the internet using ngrok: `ngrok http 3000`
6. Run `cd ..`
7. Change the IMAGE_SCANNING_URL entry in `.env` to the URL provided by ngrok
8. Restart the application: `CTRL+C` on the terminal that is running `npm run dev` and then run `npm run dev` again
9. Testing the function: Upon creating artifact, you should see a message in the terminal running `npm run dev` that says "Image scanning triggered for artifact: (artifact name)". After the scanning finishes, the terminal will log out a POST /webhook request. Check the "Vulnerabilities" tab in the application to see the results.
