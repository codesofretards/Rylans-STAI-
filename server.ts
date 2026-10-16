import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = parseInt(process.env.PORT || '3000', 10);

app.use(express.json({ limit: '10mb' }));

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'deltashield-threat-proxy', timestamp: new Date().toISOString() });
});

// Helper for VirusTotal API request
async function callVirusTotal(endpoint: string, apiKey: string, method: string = 'GET', body?: any, contentType: string = 'application/json') {
  const url = `https://www.virustotal.com/api/v3/${endpoint.replace(/^\//, '')}`;
  const headers: Record<string, string> = {
    'x-apikey': apiKey,
    'Accept': 'application/json',
  };

  const options: RequestInit = {
    method,
    headers,
  };

  if (body) {
    if (contentType === 'application/x-www-form-urlencoded') {
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      options.body = typeof body === 'string' ? body : new URLSearchParams(body).toString();
    } else {
      headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
  }

  const response = await fetch(url, options);
  const data = await response.json().catch(() => null);

  return {
    status: response.status,
    ok: response.ok,
    data,
  };
}

// 1. Validate API Key & fetch account quotas
app.post('/api/vt/validate-key', async (req, res) => {
  const apiKey = req.headers['x-apikey'] || req.body?.apiKey;
  if (!apiKey || typeof apiKey !== 'string') {
    return res.status(400).json({ error: 'VirusTotal API key is required.' });
  }

  try {
    // VT v3 user endpoint to inspect key validity and limits
    const vtRes = await callVirusTotal(`users/${encodeURIComponent(apiKey.trim())}`, apiKey.trim());
    if (!vtRes.ok) {
      return res.status(vtRes.status).json({
        error: vtRes.data?.error?.message || 'Invalid VirusTotal API Key or unauthorized.',
        details: vtRes.data
      });
    }

    return res.json({
      valid: true,
      user: {
        id: vtRes.data?.data?.id,
        user_group: vtRes.data?.data?.attributes?.user_group,
        quotas: vtRes.data?.data?.attributes?.quotas,
      }
    });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to contact VirusTotal API', message: err.message });
  }
});

// 2. Scan / Query URL
app.post('/api/vt/scan-url', async (req, res) => {
  const apiKey = (req.headers['x-apikey'] as string) || req.body?.apiKey;
  const targetUrl = req.body?.url;

  if (!apiKey) {
    return res.status(400).json({ error: 'VirusTotal API key is required.' });
  }
  if (!targetUrl || typeof targetUrl !== 'string') {
    return res.status(400).json({ error: 'Valid URL is required.' });
  }

  try {
    // Generate VirusTotal URL identifier (base64 string without trailing =)
    const normalizedUrl = targetUrl.trim();
    const urlId = Buffer.from(normalizedUrl).toString('base64').replace(/=/g, '');

    // Step A: Check if existing report exists
    let vtRes = await callVirusTotal(`urls/${urlId}`, apiKey.trim());

    if (vtRes.status === 404 || !vtRes.ok) {
      // Step B: Submit URL for scanning
      const submitRes = await callVirusTotal(
        'urls',
        apiKey.trim(),
        'POST',
        `url=${encodeURIComponent(normalizedUrl)}`,
        'application/x-www-form-urlencoded'
      );

      if (!submitRes.ok) {
        return res.status(submitRes.status).json({
          error: submitRes.data?.error?.message || 'Failed to submit URL to VirusTotal',
          details: submitRes.data
        });
      }

      const analysisId = submitRes.data?.data?.id;
      return res.json({
        status: 'queued',
        analysisId,
        urlId,
        message: 'URL queued for fresh analysis.',
        data: submitRes.data
      });
    }

    return res.json({
      status: 'completed',
      urlId,
      data: vtRes.data
    });
  } catch (err: any) {
    return res.status(500).json({ error: 'URL scan failed', message: err.message });
  }
});

// 3. Scan / Query File Hash (SHA-256 / SHA-1 / MD5)
app.post('/api/vt/scan-hash', async (req, res) => {
  const apiKey = (req.headers['x-apikey'] as string) || req.body?.apiKey;
  const hash = req.body?.hash;

  if (!apiKey) {
    return res.status(400).json({ error: 'VirusTotal API key is required.' });
  }
  if (!hash || typeof hash !== 'string') {
    return res.status(400).json({ error: 'File hash (SHA-256) is required.' });
  }

  try {
    const cleanHash = hash.trim().toLowerCase();
    const vtRes = await callVirusTotal(`files/${cleanHash}`, apiKey.trim());

    if (!vtRes.ok) {
      return res.status(vtRes.status).json({
        error: vtRes.data?.error?.message || 'File hash not found in VirusTotal database',
        status: vtRes.status,
        details: vtRes.data
      });
    }

    return res.json({
      status: 'completed',
      hash: cleanHash,
      data: vtRes.data
    });
  } catch (err: any) {
    return res.status(500).json({ error: 'File hash scan failed', message: err.message });
  }
});

// 4. Poll Analysis ID
app.post('/api/vt/analysis', async (req, res) => {
  const apiKey = (req.headers['x-apikey'] as string) || req.body?.apiKey;
  const analysisId = req.body?.analysisId;

  if (!apiKey) {
    return res.status(400).json({ error: 'VirusTotal API key is required.' });
  }
  if (!analysisId || typeof analysisId !== 'string') {
    return res.status(400).json({ error: 'Analysis ID is required.' });
  }

  try {
    const vtRes = await callVirusTotal(`analyses/${analysisId.trim()}`, apiKey.trim());
    if (!vtRes.ok) {
      return res.status(vtRes.status).json({
        error: vtRes.data?.error?.message || 'Failed to fetch analysis status',
        details: vtRes.data
      });
    }

    return res.json({
      status: vtRes.data?.data?.attributes?.status,
      data: vtRes.data
    });
  } catch (err: any) {
    return res.status(500).json({ error: 'Analysis retrieval failed', message: err.message });
  }
});

// Setup Vite middleware in dev or static files in prod
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(port, '0.0.0.0', () => {
    console.log(`DeltaShield Server running on http://0.0.0.0:${port}`);
  });
}

startServer();
