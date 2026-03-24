export default async function handler(req, res) {
    // A Vercel automaticamente roda essa função em um servidor escondido (Node.js)

    // -------------------------------------------------------------
    // PROTEÇÃO E PERMISSÃO DE DOMÍNIOS EXTERNOS (CORS)
    // -------------------------------------------------------------
    // Aqui nós estamos "Avisando a Vercel" para aceitar receber chamadas
    // vindas dos domínios do GitHub Pages ou de qualquer outro site de fora.
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*'); // Permite conexões do github.io
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, X-Turnstile-Token');

    // Navegadores fazem um "aviso prévio" de segurança chamado OPTIONS. 
    // Precisamos sempre aprovar para o CORS funcionar!
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }
    // -------------------------------------------------------------
    
    // 1. Pegamos o que o frontend enviou via URL (ex: /api/consultar?protocolo=URE-X)
    const { protocolo } = req.query;

    if (!protocolo) {
        return res.status(400).json({ erro: "Protocolo não informado." });
    }

    // -------------------------------------------------------------
    // VALIDAÇÃO ANTI-BOT (CLOUDFLARE TURNSTILE)
    // -------------------------------------------------------------
    const turnstileToken = req.headers['x-turnstile-token'];
    if (!turnstileToken) {
        return res.status(403).json({ erro: "Acesso negado: Validação Anti-Robô ausente." });
    }

    const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET_KEY || '0x4AAAAAACvc8XyS9pUWaoIQPatm9D1aXNc';

    try {
        const cfFormData = new URLSearchParams();
        cfFormData.append('secret', TURNSTILE_SECRET);
        cfFormData.append('response', turnstileToken);

        const cfRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            body: cfFormData
        });
        const cfData = await cfRes.json();
        
        if (!cfData.success) {
            return res.status(403).json({ erro: "Interceptado: O teste de humanidade falhou." });
        }
    } catch (e) {
        console.error("Erro no Cloudflare:", e);
        return res.status(500).json({ erro: "Falha ao validar sistema anti-robô." });
    }
    // -------------------------------------------------------------

    // 2. Chaves de Acesso
    // ATENÇÃO: O ideal é mover isso para o painel "Environment Variables" da Vercel depois!
    // Ex: const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_URL = process.env.SUPABASE_URL || "https://fdcxcuyxrgbpmcrryiof.supabase.co";
    const SUPABASE_KEY = process.env.SUPABASE_KEY || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZkY3hjdXl4cmdicG1jcnJ5aW9mIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzQxMTk5NTMsImV4cCI6MjA4OTY5NTk1M30.AGRudVkfcFNGTftdV02NA3Xz6Xs1WzYruqCWLVnF-Rw";

    const defaultHeaders = {
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'Content-Type': 'application/json'
    };

    try {
        const encodedProtocol = encodeURIComponent(protocolo.trim().toUpperCase());
        
        // 3. Batemos no Supabase por tráz dos panos (invisível para o usuário)
        const [resSefrep, resSeape] = await Promise.all([
            fetch(`${SUPABASE_URL}/rest/v1/sefrep_registros?protocolo=ilike.*${encodedProtocol}*&select=*`, { method: 'GET', headers: defaultHeaders }),
            fetch(`${SUPABASE_URL}/rest/v1/seape_registros?protocolo=ilike.*${encodedProtocol}*&select=*`, { method: 'GET', headers: defaultHeaders })
        ]);

        if (resSefrep.status === 429 || resSeape.status === 429) {
            return res.status(429).json({ erro: "Limite de consultas atingido no BD." });
        }

        if (!resSefrep.ok || !resSeape.ok) {
            return res.status(500).json({ erro: "Erro ao consultar as tabelas no banco de dados." });
        }

        const [dadosSefrep, dadosSeape] = await Promise.all([resSefrep.json(), resSeape.json()]);

        // 4. Juntamos as informações das duas bases
        let todosResultados = [
            ...(dadosSefrep || []).map(p => ({ ...p, origem: 'SEFREP' })),
            ...(dadosSeape || []).map(p => ({ ...p, origem: 'SEAPE' }))
        ];

        // 5. Devolvemos a lista limpa e bonita para o frontend
        return res.status(200).json(todosResultados);

    } catch (error) {
        console.error("Erro interno no Proxy Vercel:", error);
        return res.status(500).json({ erro: "Falha na comunicação Vercel <-> Supabase." });
    }
}
