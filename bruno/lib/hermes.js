// Shared helpers of the Hermes Bruno collection: request scripts load them with require("./lib/hermes").

// A JSON call to the API with the token of an environment variable (the admin's `token` by default).
async function api(bru, method, path, tokenVar, data) {
  const response = await bru.sendRequest({
    method,
    url: `${bru.getEnvVar("baseUrl")}${path}`,
    headers: { Authorization: `Bearer ${bru.getEnvVar(tokenVar || "token")}`, "Content-Type": "application/json" },
    data,
  });
  return response.data;
}

// False (and the request skipped) when an installation has no such data; an error when demo data is expected.
function needData(bru, item, what) {
  if (item) return true;
  if (Number(bru.getEnvVar("demoMinItems") || 0) > 0) throw new Error(`${what} expected with demo data`);
  bru.runner.skipRequest();
  return false;
}

// False (and the request skipped) unless stateChanging=1: the request changes data a person owns.
function optIn(bru) {
  if (String(bru.getEnvVar("stateChanging") || "0") === "1") return true;
  bru.runner.skipRequest();
  return false;
}

// The newest recommendation, picked once per run so a newer assessment stored meanwhile changes nothing.
async function recommendation(bru) {
  if (bru.getVar("assessmentId")) {
    return { assessment_id: bru.getVar("assessmentId"), asset: { ci_id: bru.getVar("assetCiId") } };
  }
  const page = await api(bru, "GET", "/api/recommendations?limit=1");
  const first = page.items[0] || null;
  bru.setVar("assessmentId", first ? first.assessment_id : "");
  bru.setVar("assetCiId", first && first.asset ? first.asset.ci_id : "");
  return first;
}

// The first vulnerability group, or null.
async function vulnerabilityGroup(bru) {
  const page = await api(bru, "GET", "/api/vulnerabilities?limit=1");
  const group = page.groups[0] || null;
  bru.setVar("groupId", group ? group.group_id : "");
  return group;
}

module.exports = { api, needData, optIn, recommendation, vulnerabilityGroup };
