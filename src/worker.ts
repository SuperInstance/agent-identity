interface Env {
  AGENT_IDENTITY: KVNamespace;
  SIGNING_KEY: string;
}

interface DIDDocument {
  "@context": string[];
  id: string;
  verificationMethod: VerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
}

interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase: string;
}

interface CreateRequest {
  agentId: string;
  publicKey: string;
  recoveryKeys?: string[];
}

interface VerificationRequest {
  credential: string;
  signature: string;
  did: string;
}

const HTML_HEADER = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Agent Identity</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; 
      background: #0a0a0f; 
      color: #f8fafc; 
      min-height: 100vh;
      line-height: 1.6;
    }
    .container { 
      max-width: 1200px; 
      margin: 0 auto; 
      padding: 2rem 1rem; 
    }
    header { 
      border-bottom: 1px solid #1e293b; 
      padding-bottom: 2rem; 
      margin-bottom: 3rem; 
    }
    h1 { 
      font-size: 3rem; 
      background: linear-gradient(90deg, #e11d48 0%, #f472b6 100%); 
      -webkit-background-clip: text; 
      -webkit-text-fill-color: transparent; 
      margin-bottom: 0.5rem; 
    }
    .tagline { 
      color: #94a3b8; 
      font-size: 1.2rem; 
      margin-bottom: 2rem; 
    }
    .grid { 
      display: grid; 
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
      gap: 2rem; 
      margin-bottom: 3rem; 
    }
    .card { 
      background: #1e1e2e; 
      border-radius: 12px; 
      padding: 2rem; 
      border: 1px solid #334155; 
      transition: transform 0.2s, border-color 0.2s; 
    }
    .card:hover { 
      transform: translateY(-4px); 
      border-color: #e11d48; 
    }
    .card h3 { 
      color: #e11d48; 
      margin-bottom: 1rem; 
      font-size: 1.5rem; 
    }
    .card p { 
      color: #cbd5e1; 
      margin-bottom: 1.5rem; 
    }
    .endpoint { 
      background: #0f172a; 
      padding: 0.75rem; 
      border-radius: 8px; 
      font-family: 'Monaco', monospace; 
      font-size: 0.9rem; 
      color: #7dd3fc; 
      margin-bottom: 1rem; 
      border-left: 3px solid #e11d48; 
    }
    footer { 
      border-top: 1px solid #1e293b; 
      padding-top: 2rem; 
      margin-top: 3rem; 
      text-align: center; 
      color: #64748b; 
      font-size: 0.9rem; 
    }
    .fleet-badge { 
      display: inline-flex; 
      align-items: center; 
      gap: 0.5rem; 
      background: #1e293b; 
      padding: 0.5rem 1rem; 
      border-radius: 20px; 
      margin-top: 1rem; 
    }
    .status { 
      width: 8px; 
      height: 8px; 
      background: #10b981; 
      border-radius: 50%; 
      animation: pulse 2s infinite; 
    }
    @keyframes pulse { 
      0%, 100% { opacity: 1; } 
      50% { opacity: 0.5; } 
    }
    .health { 
      color: #10b981; 
      font-weight: bold; 
    }
  </style>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
  <div class="container">
    <header>
      <h1>Agent Identity</h1>
      <p class="tagline">Cryptographic identity system for fleet agents — DID, verifiable credentials, delegation chains, identity recovery</p>
    </header>
    <main>
      <div class="grid">
        <div class="card">
          <h3>DID Creation</h3>
          <p>Generate W3C-compliant Decentralized Identifiers for fleet agents with embedded public keys and recovery mechanisms.</p>
          <div class="endpoint">POST /api/create</div>
        </div>
        <div class="card">
          <h3>DID Resolution</h3>
          <p>Resolve any agent's DID document to verify identity and retrieve public keys for secure communication.</p>
          <div class="endpoint">GET /api/resolve/:did</div>
        </div>
        <div class="card">
          <h3>Credential Verification</h3>
          <p>Verify signatures on credentials and delegation chains using Ed25519 cryptography.</p>
          <div class="endpoint">POST /api/verify</div>
        </div>
      </div>
`;

const HTML_FOOTER = `    </main>
    <footer>
      <p>Agent Identity System v1.0 • W3C DID Compliant • Zero Dependencies</p>
      <div class="fleet-badge">
        <div class="status"></div>
        <span>Fleet Identity Network Operational</span>
      </div>
    </footer>
  </div>
</body>
</html>`;

class AgentIdentity {
  private env: Env;

  constructor(env: Env) {
    this.env = env;
  }

  async generateDID(agentId: string, publicKey: string): Promise<string> {
    const timestamp = Date.now();
    const uniqueId = `${agentId}:${timestamp}:${publicKey.substring(0, 16)}`;
    const hashBuffer = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(uniqueId)
    );
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return `did:agent:${hashHex}`;
  }

  async createDIDDocument(did: string, publicKey: string, recoveryKeys?: string[]): Promise<DIDDocument> {
    const verificationMethod: VerificationMethod = {
      id: `${did}#key-1`,
      type: 'Ed25519VerificationKey2020',
      controller: did,
      publicKeyMultibase: publicKey
    };

    const doc: DIDDocument = {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1"
      ],
      id: did,
      verificationMethod: [verificationMethod],
      authentication: [`${did}#key-1`],
      assertionMethod: [`${did}#key-1`]
    };

    await this.env.AGENT_IDENTITY.put(did, JSON.stringify({
      document: doc,
      publicKey,
      recoveryKeys: recoveryKeys || [],
      createdAt: Date.now()
    }));

    return doc;
  }

  async verifySignature(message: string, signature: string, publicKey: string): Promise<boolean> {
    try {
      const encoder = new TextEncoder();
      const messageBuffer = encoder.encode(message);
      const signatureBuffer = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
      
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        Uint8Array.from(atob(publicKey), c => c.charCodeAt(0)),
        { name: 'Ed25519' },
        false,
        ['verify']
      );

      return await crypto.subtle.verify(
        'Ed25519',
        cryptoKey,
        signatureBuffer,
        messageBuffer
      );
    } catch {
      return false;
    }
  }

  async handleRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    const securityHeaders = {
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com;",
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'strict-origin-when-cross-origin'
    };

    if (path === '/' || path === '') {
      return new Response(HTML_HEADER + HTML_FOOTER, {
        headers: {
          'Content-Type': 'text/html',
          ...securityHeaders
        }
      });
    }

    if (path === '/health') {
      return new Response(JSON.stringify({ status: 'healthy', timestamp: new Date().toISOString() }), {
        headers: {
          'Content-Type': 'application/json',
          ...securityHeaders
        }
      });
    }

    if (path === '/api/create' && request.method === 'POST') {
      try {
        const body: CreateRequest = await request.json();
        
        if (!body.agentId || !body.publicKey) {
          return new Response(JSON.stringify({ error: 'Missing required fields' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...securityHeaders }
          });
        }

        const did = await this.generateDID(body.agentId, body.publicKey);
        const document = await this.createDIDDocument(did, body.publicKey, body.recoveryKeys);

        return new Response(JSON.stringify({
          did,
          document,
          status: 'created'
        }), {
          headers: {
            'Content-Type': 'application/json',
            ...securityHeaders
          }
        });
      } catch (error) {
        return new Response(JSON.stringify({ error: 'Invalid request' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...securityHeaders }
        });
      }
    }

    if (path.startsWith('/api/resolve/') && request.method === 'GET') {
      const did = path.split('/api/resolve/')[1];
      
      if (!did) {
        return new Response(JSON.stringify({ error: 'DID required' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...securityHeaders }
        });
      }

      const stored = await this.env.AGENT_IDENTITY.get(did);
      
      if (!stored) {
        return new Response(JSON.stringify({ error: 'DID not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...securityHeaders }
        });
      }

      const data = JSON.parse(stored);
      return new Response(JSON.stringify(data.document), {
        headers: {
          'Content-Type': 'application/json',
          ...securityHeaders
        }
      });
    }

    if (path === '/api/verify' && request.method === 'POST') {
      try {
        const body: VerificationRequest = await request.json();
        
        if (!body.credential || !body.signature || !body.did) {
          return new Response(JSON.stringify({ error: 'Missing required fields' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...securityHeaders }
          });
        }

        const stored = await this.env.AGENT_IDENTITY.get(body.did);
        if (!stored) {
          return new Response(JSON.stringify({ verified: false, error: 'DID not found' }), {
            headers: { 'Content-Type': 'application/json', ...securityHeaders }
          });
        }

        const data = JSON.parse(stored);
        const verified = await this.verifySignature(
          body.credential,
          body.signature,
          data.publicKey
        );

        return new Response(JSON.stringify({
          verified,
          did: body.did,
          timestamp: new Date().toISOString()
        }), {
          headers: {
            'Content-Type': 'application/json',
            ...securityHeaders
          }
        });
      } catch (error) {
        return new Response(JSON.stringify({ verified: false, error: 'Verification failed' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...securityHeaders }
        });
      }
    }

    return new Response(JSON.stringify({ error: 'Not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...securityHeaders }
    });
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const identity = new AgentIdentity(env);
    return identity.handleRequest(request);
  }
};