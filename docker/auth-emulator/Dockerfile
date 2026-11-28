# Firebase Auth emulator for backend tests only (D-069): issues test ID tokens per role, no network.
FROM node:22-slim@sha256:be979e5523c76fa4d5ca4ebd3099078f220aa47ec39c48ad5b5df9314debd6eb
# Debian security updates published after the pinned base was built (fixable Trivy findings such as libpam and
# zstd); the base digest is the newest build of its tag, so they are applied here.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -o Dpkg::Options::=--force-confold \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /emulator
# firebase-tools is pinned in package.json and package-lock.json, so Dependabot can track it.
COPY package.json package-lock.json ./
# npm and yarn are only needed to install: the runtime never calls them, and their bundled dependencies carry
# fixable HIGH findings (Trivy, docs/14 §10.4), so they are removed from the image.
RUN npm ci --omit=dev --no-fund --no-audit && npm cache clean --force \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-* \
      /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg
COPY firebase.json .firebaserc ./
RUN chown -R node:node /emulator
ENV PATH="/emulator/node_modules/.bin:${PATH}"
USER node
EXPOSE 9099
HEALTHCHECK --interval=5s --timeout=3s --retries=20 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:9099/').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]
CMD ["firebase", "emulators:start", "--only", "auth", "--project", "demo-hermes"]
