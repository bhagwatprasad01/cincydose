# CincyDose web server (cincydose.org): passwordless accounts + app hosting. No npm dependencies.
FROM node:22-alpine
ENV NODE_ENV=production PORT=8080 DB_PATH=/data/cincydose.db MAIL_LOG=/data/mail.log
WORKDIR /srv/cincydose
COPY server.js package.json ./
COPY app ./app
RUN addgroup -S app && adduser -S app -G app && mkdir -p /data && chown app:app /data
USER app
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:8080/health || exit 1
CMD ["node", "--no-warnings", "server.js"]
