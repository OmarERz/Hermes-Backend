# Firebase Auth emulator for backend tests only (D-069): issues test ID tokens per role, no network.
FROM node:22-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee
ARG FIREBASE_TOOLS_VERSION=15.37.0
RUN npm install --global --no-fund --no-audit "firebase-tools@${FIREBASE_TOOLS_VERSION}" && npm cache clean --force
WORKDIR /emulator
COPY firebase.json .firebaserc ./
RUN chown -R node:node /emulator
USER node
EXPOSE 9099
HEALTHCHECK --interval=5s --timeout=3s --retries=20 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:9099/').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]
CMD ["firebase", "emulators:start", "--only", "auth", "--project", "demo-hermes"]
