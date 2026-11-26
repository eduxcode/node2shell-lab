'use strict';

const express = require('express');

const app = express();

app.get('/health', (_request, response) => {
  response.type('text/plain').send('PONG\n');
});

// Any POST body with Content-Encoding: br is inflated by express.json()
// (body-parser 2.x) before the route handler runs.
app.post('/upload', express.json(), (_request, response) => {
  response.type('text/plain').send('DONE\n');
});

app.use((error, _request, response, _next) => {
  const code = error.code || error.type || error.message || 'ERROR';
  response.status(400).type('text/plain').send(`ERR ${code}\n`);
});

app.listen(3000, '0.0.0.0', () => {
  console.error(`[target] node ${process.version} listening on :3000`);
});
