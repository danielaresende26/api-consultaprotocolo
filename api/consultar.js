// =========================================================================
// MÓDULO DE RATE LIMITING (Proteção contra abuso por IP)
// =========================================================================
// Armazena contadores por IP. Na Vercel serverless, cada instância mantém
// seu próprio Map. Numa instância quente, bloqueia rajadas de um mesmo IP.
// Limite: 10 consultas por IP a cada 2 minutos.
const rateLimitMap = new Map();
const RATE_LIMIT_MAX = 10;       // máximo de requisições
const RATE_LIMIT_WINDOW = 120000; // janela de 2 minutos (ms)

function verificarRateLimit(ip) {
    const agora = Date.now();
    const registro = rateLimitMap.get(ip);

    if (!registro || (agora - registro.inicio) > RATE_LIMIT_WINDOW) {
        rateLimitMap.set(ip, { contador: 1, inicio: agora });
        return true;
    }

    if (registro.contador >= RATE_LIMIT_MAX) {
        return false; // BLOQUEADO
    }

    registro.contador++;
    return true;
}

// Limpa IPs antigos a cada 5 minutos para não acumular memória
setInterval(() => {
    const agora = Date.now();
    for (const [ip, reg] of rateLimitMap) {
        if ((agora - reg.inicio) > RATE_LIMIT_WINDOW * 2) {
            rateLimitMap.delete(ip);
        }
    }
}, 300000);

// =========================================================================
// FUNÇÃO PRINCIPAL DO PROXY SEGURO
// =========================================================================
export default async function handler(req, res) {

    // -------------------------------------------------------------
    // PROTEÇÃO CORS (Somente domínio oficial)
    // -------------------------------------------------------------
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', 'https://ure-suzano.github.io');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, X-Turnstile-Token');

    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    // -------------------------------------------------------------
    // RATE LIMITING POR IP
    // -------------------------------------------------------------
    const ipCliente = req.headers['x-forwarded-for']?.split(',')[0]?.trim() 
                   || req.headers['x-real-ip'] 
                   || req.socket?.remoteAddress 
                   || 'desconhecido';

    if (!verificarRateLimit(ipCliente)) {
        return res.status(429).json({ 
            erro: "⚠️ Limite de consultas atingido. Você realizou muitas buscas em pouco tempo. Aguarde 2 minutos e tente novamente." 
        });
    }

    // 1. Protocolo informado pelo frontend
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

    // 2. Chaves de Acesso (Exclusivamente de variáveis de ambiente)
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

        // =============================================================
        // MÓDULO DE AUDITORIA LGPD (Art. 37 — Registro de Operações)
        // Grava log de cada consulta no Supabase de forma assíncrona
        // (fire-and-forget: NÃO bloqueia a resposta ao usuário)
        // =============================================================
        try {
            const registroAuditoria = {
                ip_hash: ipCliente.substring(0, 3) + '***' + ipCliente.slice(-2), // IP mascarado (LGPD)
                protocolo_consultado: protocolo.trim().toUpperCase(),
                resultados_encontrados: todosResultados.length,
                data_consulta: new Date().toISOString()
            };

            // Dispara e esquece — não espera resposta para não atrasar o usuário
            fetch(`${SUPABASE_URL}/rest/v1/audit_consultas`, {
                method: 'POST',
                headers: { ...defaultHeaders, 'Prefer': 'return=minimal' },
                body: JSON.stringify(registroAuditoria)
            }).catch(err => console.error("Falha silenciosa no log de auditoria:", err));
        } catch (auditErr) {
            console.error("Erro no módulo de auditoria:", auditErr);
        }

        // 5. Devolvemos a lista limpa e enriquecida para o frontend
        return res.status(200).json(todosResultados);

    } catch (error) {
        console.error("Erro interno no Proxy Vercel:", error);
        return res.status(500).json({ erro: "Falha na comunicação Vercel <-> Supabase." });
    }
}
