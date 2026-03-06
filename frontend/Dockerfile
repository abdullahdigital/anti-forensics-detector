# Stage 1: Build the Angular app
FROM node:18-alpine as build

WORKDIR /app

COPY package*.json ./

RUN npm ci

COPY . .

# Build the Angular application
RUN npm run build -- --configuration production

# Stage 2: Serve the app with Nginx
FROM nginx:alpine

# Copy the build output to replace the default nginx contents
# Note: Ensure that the 'dist/frontend' or the correct output directory matches your angular.json OUT_DIR
COPY --from=build /app/dist/*/browser /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
