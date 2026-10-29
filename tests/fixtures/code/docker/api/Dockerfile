FROM node:22-slim AS build
WORKDIR /app
COPY . .
RUN npm ci && npm run build

# ruleid: docker/root-user
FROM node:22-slim
WORKDIR /app
COPY --from=build /app/dist ./dist
# ruleid: docker/curl-pipe-shell
RUN curl -fsSL https://get.example.com/agent.sh \
    | bash
# ruleid: docker/add-remote
ADD https://example.com/tool.tar.gz /opt/tool.tar.gz
# ok: docker/add-remote
ADD --checksum=sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc68d https://example.com/tool.tar.gz /opt/
# ruleid: secret/hardcoded-password
ENV PARTNER_API_KEY=Vb7Kq2Mx9Lt4Rz8Np3Wc6Hd1
# ok: secret/hardcoded-password
ARG NPM_TOKEN
CMD ["node", "dist/main.js"]
