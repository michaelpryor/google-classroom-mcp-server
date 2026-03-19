import crypto from 'crypto';
import express from 'express';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';

const LOGIN_PAGE_HTML = `<!DOCTYPE html>
<html>
<head>
    <title>Google Classroom MCP - Authorize</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 400px; margin: 80px auto; padding: 0 20px; }
        h2 { color: #333; }
        input[type="password"] { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
        button { background: #1a73e8; color: white; border: none; padding: 10px 24px; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #1557b0; }
        .error { color: #c00; }
    </style>
</head>
<body>
    <h2>Authorize MCP Access</h2>
    <p>Enter your password to grant access to your Google Classroom data.</p>
    {{ERROR}}
    <form method="POST" action="/login">
        <input type="hidden" name="session" value="{{SESSION_ID}}">
        <input type="password" name="password" placeholder="Your password" required autofocus>
        <button type="submit">Authorize</button>
    </form>
</body>
</html>`;

function renderLoginPage(sessionId, error = '') {
  return LOGIN_PAGE_HTML
    .replace('{{SESSION_ID}}', sessionId)
    .replace('{{ERROR}}', error);
}

function safeCompare(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

class SimpleOAuthProvider {
  constructor(signingKey) {
    this.signingKey = signingKey;
    this.clients = new Map();
    this.authCodes = new Map();
    this.pendingAuth = new Map();
  }

  _signToken(payload) {
    const sorted = Object.keys(payload).sort().reduce((acc, key) => {
      acc[key] = payload[key];
      return acc;
    }, {});
    const payloadJson = JSON.stringify(sorted);
    const payloadB64 = Buffer.from(payloadJson).toString('base64url');
    const sig = crypto.createHmac('sha256', this.signingKey).update(payloadB64).digest('hex');
    return `${payloadB64}.${sig}`;
  }

  _verifyToken(token) {
    try {
      const lastDot = token.lastIndexOf('.');
      if (lastDot === -1) return null;
      const payloadB64 = token.slice(0, lastDot);
      const sig = token.slice(lastDot + 1);
      const expectedSig = crypto.createHmac('sha256', this.signingKey).update(payloadB64).digest('hex');
      if (!safeCompare(sig, expectedSig)) return null;
      const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
      if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
      return payload;
    } catch {
      return null;
    }
  }

  registerClient(metadata) {
    const clientId = crypto.randomBytes(16).toString('base64url');
    const clientSecret = crypto.randomBytes(32).toString('base64url');
    const client = {
      ...metadata,
      client_id: clientId,
      client_secret: clientSecret,
      client_id_issued_at: Math.floor(Date.now() / 1000),
    };
    this.clients.set(clientId, client);
    return client;
  }

  startAuthorize(clientId, codeChallenge, redirectUri, state, scopes) {
    const sessionId = crypto.randomBytes(32).toString('base64url');
    this.pendingAuth.set(sessionId, { clientId, codeChallenge, redirectUri, state, scopes });
    return sessionId;
  }

  completeAuthorize(sessionId, userId) {
    const pending = this.pendingAuth.get(sessionId);
    if (!pending) return null;
    this.pendingAuth.delete(sessionId);
    const code = crypto.randomBytes(32).toString('base64url');
    this.authCodes.set(code, { ...pending, userId, expiresAt: Math.floor(Date.now() / 1000) + 300 });
    return { code, redirectUri: pending.redirectUri, state: pending.state };
  }

  exchangeCode(code, clientId, codeVerifier, redirectUri) {
    const authCode = this.authCodes.get(code);
    if (!authCode) return { error: 'invalid_grant' };
    this.authCodes.delete(code);
    if (authCode.expiresAt < Math.floor(Date.now() / 1000)) return { error: 'invalid_grant' };
    if (authCode.clientId !== clientId) return { error: 'invalid_grant' };
    if (authCode.redirectUri !== redirectUri) return { error: 'invalid_grant' };
    const expected = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    if (expected !== authCode.codeChallenge) return { error: 'invalid_grant' };
    return { tokens: this._issueTokens(clientId, authCode.scopes, authCode.userId) };
  }

  refresh(refreshTokenStr, clientId) {
    const payload = this._verifyToken(refreshTokenStr);
    if (!payload || payload.type !== 'refresh') return { error: 'invalid_grant' };
    return { tokens: this._issueTokens(clientId, payload.scopes || [], payload.user_id) };
  }

  validateToken(token) {
    const payload = this._verifyToken(token);
    if (!payload || payload.type !== 'access') return null;
    return payload;
  }

  _issueTokens(clientId, scopes, userId) {
    const now = Math.floor(Date.now() / 1000);
    const result = {
      access_token: this._signToken({ client_id: clientId, exp: now + 86400, scopes, type: 'access', user_id: userId }),
      token_type: 'bearer',
      expires_in: 86400,
      refresh_token: this._signToken({ client_id: clientId, exp: now + 86400 * 30, scopes, type: 'refresh', user_id: userId }),
    };
    if (scopes && scopes.length) result.scope = scopes.join(' ');
    return result;
  }
}

/**
 * @param {function} createServer - Factory: (userId) => McpServer configured for that user
 * @param {Map<string, {password: string, refreshToken: string}>} users - User configs keyed by userId
 * @param {string} signingKey - Key for HMAC token signing
 */
export function createHttpApp(createServer, users, signingKey) {
  const oauth = new SimpleOAuthProvider(signingKey);
  const app = express();
  const transports = new Map();

  app.set('trust proxy', 1);
  app.use(express.json({ limit: '4mb' }));
  app.use(express.urlencoded({ extended: true }));

  // Find user by password (timing-safe check against all users)
  function findUserByPassword(password) {
    let matchedUserId = null;
    for (const [userId, config] of users) {
      if (safeCompare(password || '', config.password)) {
        matchedUserId = userId;
      }
    }
    return matchedUserId;
  }

  // OAuth metadata
  app.get('/.well-known/oauth-authorization-server', (req, res) => {
    const serverUrl = `${req.protocol}://${req.get('host')}`;
    res.json({
      issuer: serverUrl,
      authorization_endpoint: `${serverUrl}/authorize`,
      token_endpoint: `${serverUrl}/token`,
      registration_endpoint: `${serverUrl}/register`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
      code_challenge_methods_supported: ['S256'],
    });
  });

  app.get('/.well-known/oauth-protected-resource', (req, res) => {
    const serverUrl = `${req.protocol}://${req.get('host')}`;
    res.json({
      resource: serverUrl,
      authorization_servers: [serverUrl],
      bearer_methods_supported: ['header'],
    });
  });

  // Dynamic client registration
  app.post('/register', (req, res) => {
    const client = oauth.registerClient(req.body);
    res.status(201).json(client);
  });

  // Authorization endpoint
  app.get('/authorize', (req, res) => {
    const { client_id, code_challenge, redirect_uri, state, scope } = req.query;
    if (!client_id || !oauth.clients.has(client_id)) {
      return res.status(400).json({ error: 'invalid_client' });
    }
    const sessionId = oauth.startAuthorize(
      client_id,
      code_challenge || '',
      redirect_uri || '',
      state,
      scope ? String(scope).split(' ') : []
    );
    res.redirect(`/login?session=${sessionId}`);
  });

  // Login page
  app.get('/login', (req, res) => {
    res.send(renderLoginPage(req.query.session || '', ''));
  });

  app.post('/login', (req, res) => {
    const { session, password } = req.body;
    const userId = findUserByPassword(password);
    if (!userId) {
      return res.status(403).send(
        renderLoginPage(session, '<p class="error">Invalid password. Please try again.</p>')
      );
    }
    const result = oauth.completeAuthorize(session, userId);
    if (!result) {
      return res.status(400).send('Invalid or expired session.');
    }
    const params = new URLSearchParams({ code: result.code });
    if (result.state) params.set('state', result.state);
    res.redirect(302, `${result.redirectUri}?${params}`);
  });

  // Token endpoint
  app.post('/token', (req, res) => {
    const { grant_type, client_id, code, code_verifier, redirect_uri, refresh_token } = req.body;
    if (grant_type === 'authorization_code') {
      const result = oauth.exchangeCode(code, client_id || '', code_verifier || '', redirect_uri || '');
      if (result.error) return res.status(400).json({ error: result.error });
      return res.json(result.tokens);
    }
    if (grant_type === 'refresh_token') {
      const result = oauth.refresh(refresh_token || '', client_id || '');
      if (result.error) return res.status(400).json({ error: result.error });
      return res.json(result.tokens);
    }
    res.status(400).json({ error: 'unsupported_grant_type' });
  });

  // Bearer auth middleware — attaches userId to req
  function requireAuth(req, res, next) {
    const serverUrl = `${req.protocol}://${req.get('host')}`;
    const wwwAuth = `Bearer resource_metadata="${serverUrl}/.well-known/oauth-protected-resource"`;
    const authHeader = req.headers.authorization || '';
    if (!authHeader.startsWith('Bearer ')) {
      res.set('WWW-Authenticate', wwwAuth);
      return res.status(401).json({ error: 'Missing bearer token' });
    }
    const token = authHeader.slice(7);
    const payload = oauth.validateToken(token);
    if (!payload) {
      res.set('WWW-Authenticate', wwwAuth);
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    req.userId = payload.user_id;
    next();
  }

  // SSE endpoint
  app.get('/sse', requireAuth, async (req, res) => {
    const userId = req.userId;
    console.error(`New SSE connection for user: ${userId}`);
    const transport = new SSEServerTransport('/messages', res);
    transports.set(transport.sessionId, transport);
    res.on('close', () => {
      console.error(`SSE connection closed: ${transport.sessionId} (user: ${userId})`);
      transports.delete(transport.sessionId);
    });
    const server = createServer(userId);
    await server.connect(transport);
  });

  // Message endpoint
  app.post('/messages', requireAuth, async (req, res) => {
    const sessionId = req.query.sessionId;
    const transport = transports.get(sessionId);
    if (!transport) {
      return res.status(400).json({ error: 'Unknown session' });
    }
    await transport.handlePostMessage(req, res, req.body);
  });

  // Health check
  app.get('/health', (req, res) => {
    res.json({ status: 'ok', server: 'google-classroom-mcp' });
  });

  return app;
}
