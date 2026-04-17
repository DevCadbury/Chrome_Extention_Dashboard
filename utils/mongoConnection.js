const dns = require("dns");
const dnsPromises = dns.promises;
const mongoose = require("mongoose");

const SRV_NOT_FOUND_CODES = new Set(["ENOTFOUND", "ENODATA", "EAI_NODATA"]);
const DEFAULT_DNS_SERVERS = ["8.8.8.8", "1.1.1.1"];

let dnsServersConfigured = false;

function configureDnsServers() {
  if (dnsServersConfigured) {
    return;
  }

  const configuredServers = (process.env.MONGO_DNS_SERVERS || "")
    .split(",")
    .map((server) => server.trim())
    .filter(Boolean);

  const servers = configuredServers.length > 0 ? configuredServers : DEFAULT_DNS_SERVERS;

  try {
    dns.setServers(servers);
  } catch (error) {
    console.warn(
      `⚠️ Unable to set DNS servers for MongoDB SRV lookup: ${error.message}`
    );
  }

  dnsServersConfigured = true;
}

function normalizeUri(uri) {
  if (!uri || typeof uri !== "string") {
    return "";
  }

  return uri.trim().replace(/^['\"]|['\"]$/g, "");
}

function getHostnameFromUri(uri) {
  try {
    return new URL(uri).hostname;
  } catch {
    return "";
  }
}

async function canResolveSrvRecord(uri) {
  if (!uri.startsWith("mongodb+srv://")) {
    return true;
  }

  const hostname = getHostnameFromUri(uri);
  if (!hostname) {
    return false;
  }

  try {
    await dnsPromises.resolveSrv(`_mongodb._tcp.${hostname}`);
    return true;
  } catch (error) {
    if (SRV_NOT_FOUND_CODES.has(error.code)) {
      return false;
    }

    throw error;
  }
}

function collectMongoUris(defaultUri) {
  const envUris = [
    normalizeUri(process.env.MONGODB_URI),
    normalizeUri(process.env.MONGO_URI),
  ].filter(Boolean);

  const uniqueEnvUris = [...new Set(envUris)];
  if (uniqueEnvUris.length > 0) {
    return uniqueEnvUris;
  }

  const fallbackUri = normalizeUri(defaultUri);
  return fallbackUri ? [fallbackUri] : [];
}

async function connectMongoDB({ defaultUri, options } = {}) {
  configureDnsServers();

  const uriCandidates = collectMongoUris(defaultUri);

  if (uriCandidates.length === 0) {
    throw new Error("MongoDB URI is missing. Set MONGO_URI or MONGODB_URI.");
  }

  const unresolvedSrvHosts = [];
  const connectionErrors = [];

  for (const uri of uriCandidates) {
    const hostname = getHostnameFromUri(uri) || "unknown-host";
    let srvResolvable = true;

    try {
      srvResolvable = await canResolveSrvRecord(uri);
    } catch (error) {
      connectionErrors.push(
        `${hostname}: SRV DNS lookup failed (${error.code || "UNKNOWN"}: ${
          error.message
        })`
      );
      continue;
    }

    if (!srvResolvable) {
      unresolvedSrvHosts.push(hostname);
      continue;
    }

    try {
      await mongoose.connect(uri, {
        serverSelectionTimeoutMS: 10000,
        ...options,
      });

      return { uri, hostname };
    } catch (error) {
      connectionErrors.push(`${hostname}: ${error.message}`);

      if (mongoose.connection.readyState !== 0) {
        await mongoose.disconnect().catch(() => {});
      }
    }
  }

  if (
    unresolvedSrvHosts.length > 0 &&
    unresolvedSrvHosts.length === uriCandidates.length
  ) {
    throw new Error(
      `MongoDB SRV hostname not found: ${unresolvedSrvHosts.join(
        ", "
      )}. Update MONGO_URI/MONGODB_URI with a valid Atlas connection string.`
    );
  }

  if (connectionErrors.length > 0) {
    throw new Error(
      `MongoDB connection failed for all configured URIs. ${connectionErrors.join(
        " | "
      )}`
    );
  }

  throw new Error("MongoDB connection failed. Check your URI configuration.");
}

module.exports = {
  connectMongoDB,
  collectMongoUris,
};