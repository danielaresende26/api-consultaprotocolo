export default async function handler(req, res) {
    // A Vercel automaticamente roda essa função em um servidor escondido (Node.js)

    // -------------------------------------------------------------
    // PROTEÇÃO E PERMISSÃO DE DOMÍNIOS EXTERNOS (CORS)
    // -------------------------------------------------------------
    // Aqui nós estamos "Avisando a Vercel" para aceitar receber chamadas
    // vindas dos domínios do GitHub Pages ou de qualquer outro site de fora.
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', 'https://uresuzano.github.io'); // Restrição CORS: somente o domínio oficial
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

    const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET_KEY;
    if (!TURNSTILE_SECRET) {
        return res.status(500).json({ erro: "Configuração do servidor incompleta (Anti-Bot)." });
    }

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
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_KEY = process.env.SUPABASE_KEY;
    if (!SUPABASE_URL || !SUPABASE_KEY) {
        return res.status(500).json({ erro: "Configuração do servidor incompleta (BD)." });
    }

    const defaultHeaders = {
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'Content-Type': 'application/json'
    };

    try {
        const encodedProtocol = encodeURIComponent(protocolo.trim().toUpperCase());
        
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

        let todosResultados = [
            ...(dadosSefrep || []).map(p => ({ ...p, origem: 'SEFREP' })),
            ...(dadosSeape || []).map(p => ({ ...p, origem: 'SEAPE' }))
        ];

        // --- CÁLCULO DE FILA NO BACKEND ---
        // Se algum dos resultados for um VTC em Análise, buscamos a fila global no banco para calcular a posição
        const temVtcAtivo = todosResultados.some(p => {
            const tema = (p.tema || "").toUpperCase();
            const obs = (p.observacoes || "").toLowerCase();
            return tema.includes("VTC") && 
                   !obs.includes("finalizado") && !obs.includes("concluida") && !obs.includes("concluido") &&
                   !obs.includes("devolvido") && !obs.includes("não faz jus") && !obs.includes("nao faz jus");
        });

        if (temVtcAtivo) {
            const resFila = await fetch(`${SUPABASE_URL}/rest/v1/sefrep_registros?tema=ilike.*VTC*&or=(status.ilike.*lise*,status.ilike.*andamento*,status.ilike.*exig*)&select=*`, { method: 'GET', headers: defaultHeaders });
            if (resFila.ok) {
                let filaAtivaVTC = await resFila.json();
                filaAtivaVTC.sort((a, b) => {
                    const d1 = new Date(a.data_entrada || 0).getTime();
                    const d2 = new Date(b.data_entrada || 0).getTime();
                    if (d1 === d2) {
                        return new Date(a.created_at || 0).getTime() - new Date(b.created_at || 0).getTime();
                    }
                    return d1 - d2;
                });

                todosResultados = todosResultados.map(p => {
                    const isEmAnaliseVTC = (p.tema || "").toUpperCase().includes("VTC") && 
                        !(p.observacoes || "").toLowerCase().includes("finalizado") &&
                        !(p.observacoes || "").toLowerCase().includes("devolvido") &&
                        !(p.observacoes || "").toLowerCase().includes("não faz jus");
                    
                    if (isEmAnaliseVTC) {
                        const indexNaFila = filaAtivaVTC.findIndex(f => f.id === p.id);
                        if (indexNaFila >= 0) {
                            p._posicaoFila = indexNaFila + 1;
                            
                            const dataEntradaReal = p.data_entrada ? new Date(p.data_entrada) : new Date();
                            const diasDecorridos = Math.floor((new Date() - dataEntradaReal) / (1000 * 60 * 60 * 24));
                            let diasEst = 60 + Math.floor(indexNaFila * 0.25) - diasDecorridos;
                            if (diasEst > 120) diasEst = 120;
                            if (diasEst < 30) diasEst = 30;
                            p._diasEstimados = diasEst;
                        }
                    }
                    return p;
                });
            }
        }

        // 5. Devolvemos a lista limpa e enriquecida para o frontend
        return res.status(200).json(todosResultados);

    } catch (error) {
        console.error("Erro interno no Proxy Vercel:", error);
        return res.status(500).json({ erro: "Falha na comunicação Vercel <-> Supabase." });
    }
}
