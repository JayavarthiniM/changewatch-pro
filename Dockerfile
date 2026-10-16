FROM mcr.microsoft.com/playwright:v1.51.1-noble
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY . .
ENV NODE_ENV=production PORT=3000 TZ=Asia/Kolkata
EXPOSE 3000
CMD ["node", "server.js"]
