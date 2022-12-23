import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { parse } from 'date-format-parse';
import { Tail } from 'tail';
import express from 'express';
import sqlite3 from 'sqlite3';
import fetch from 'node-fetch';
import geoip from 'fast-geoip';
import path from 'path';
import dns from 'dns';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const dnsPromises = dns.promises;
const app = express();

let ipv6geo_cache = {};

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, '/index.html'));
});

app.get("/viewers", (req, res) => {
  db.all(`SELECT ip FROM requests WHERE datetime(timestamp) >= datetime('now', '-30 seconds') GROUP BY ip ORDER BY timestamp DESC`, (err, rows) => {
    if (err) {
      return res.send(err);
    }
    res.send({viewers: rows.length });
  });
});

app.get("/stats", (req, res) => {
  db.all(`SELECT * FROM requests WHERE datetime(timestamp) >= datetime('now', '-30 seconds') GROUP BY ip ORDER BY ip DESC`, (err, rows) => {
    if (err) {
      return res.send(err);
    }
    res.send(rows);
  });
});

app.get("/ipv6cache", (req, res) => {
  res.send(ipv6geo_cache);
});

app.listen(3000);

dns.setServers(['173.230.145.5', '2600:3c01::2', '173.230.147.5', '2600:3c01::9', '173.230.155.5', '2600:3c01::5', '173.255.212.5', '2600:3c01::7', '173.255.219.5', '2600:3c01::3']);

const db = new sqlite3.Database('stats.db');

db.run(`CREATE TABLE IF NOT EXISTS requests (ip TEXT, path TEXT, city TEXT, country TEXT, ll TEXT, ua TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`);

const regex = /(?<ipaddress>.+) - - \[(?<datetime>[^\]]+)\] \"(?<url>[^\"]+)\" \d+ [0-9]+ \"(?<ref>[^\"]+)\" \"(?<ua>[^\"]+)\"/;

const tail = new Tail("/var/log/nginx/access.log");

tail.on("line", async function(data) {
  let raw = regex.exec(data);
  if (raw && raw.groups) {
    let parsed = await parseResults(raw.groups);
    if (parsed.islive) {
      db.run(`INSERT INTO requests (ip, path, city, country, ll, ua) VALUES (?, ?, ?, ?, ?, ?)`, [parsed.ip, parsed.channel, parsed.geo.city, parsed.geo.country, parsed.geo.ll, parsed.useragent]);
    }
  } else {
    console.log(data);
    console.log('------------------------------[RECORD BOUNDRY]-----------')
  }
});

tail.on("error", function(error) {
  console.log('ERROR: ', error);
});

async function getGeoip(ip) {
  if (ip.includes(':')) {
    if (ipv6geo_cache[ip]) {
      return ipv6geo_cache[ip];
    } else {
      const response = await fetch(`https://ip.seeip.org/geoip/${ip}`);
      const data = await response.json();
      let result = {
        country: data.country_code ?? '',
        timezone: data.timezone ?? '',
        city: data.city ?? '',
        ll: [data.latitude, data.longitude]
      };
      ipv6geo_cache[ip] = result;
      return result;
    }
  } else { // IPv4
    let result = await geoip.lookup(ip);
    delete result.range;
    delete result.region;
    delete result.metro;
    delete result.area;
    delete result.eu;
    return result;
  }
}

async function parseResults(res) {
  let output = {};
  let dnsResult;

  try {
    dnsResult = await dnsPromises.reverse(res.ipaddress);
  } catch (e) {
    dnsResult = [];
  }

  const splitStr = res.url.split(" ");
  const urlObj = { method: splitStr[0], url: splitStr[1], httpversion: splitStr[2] };

  output.ip = res.ipaddress;
  output.dns = dnsResult;
  output.geo = await getGeoip(res.ipaddress);
  output.timestamp = parse(res.datetime, "DD/MMM/YYYY:HH:mm:ss ZZ");
  output.request = urlObj;
  output.isimpression = urlObj.url && urlObj.url.startsWith('/live/') && urlObj.url.endsWith('index.m3u8');
  output.islive = urlObj.url && urlObj.url.startsWith('/live/') && urlObj.url.endsWith('.ts');
  output.channel = output.islive | output.isimpression ? /\/live\/(.+)\/.+\..{2,4}/.exec(urlObj.url)[1] : null;
  output.referrer = res.ref;
  output.useragent = res.ua;

  return output;
}