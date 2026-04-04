// ========================================================================= 
// MÓDULO DE RATE LIMITING (Proteção contra abuso por IP) 
// ========================================================================= 
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
  
// Limpeza periódica de memória
if (typeof setInterval !== 'undefined') {
    setInterval(() => { 
        const agora = Date.now(); 
        for (const [ip, reg] of rateLimitMap) { 
            if ((agora - reg.inicio) > RATE_LIMIT_WINDOW * 2) { 
                rateLimitMap.delete(ip); 
            } 
        } 
    }, 300000);
}

// ========================================================================= 
// MÓDULO DE PRIVACIDADE (Máscara de Nome - LGPD)
// ========================================================================= 
function aplicarMascaraNome(nomeCompleto) {
    if (!nomeCompleto) return "INTERESSADO NÃO INFORMADO";
    const partes = nomeCompleto.trim().split(/\s+/);
    // Retorna Primeiro + Segundo nome (se existir) + reticências
    if (partes.length >= 2) {
        return `${partes[0].toUpperCase()} ${partes[1].toUpperCase()} ...`;
    }
    return partes[0].toUpperCase() + " ...";
}

// ========================================================================= 
// FUNÇÃO PRINCIPAL DO PROXY SEGURO 
// ========================================================================= 
export default async function handler(req, res) { 
  
    // 1. Configuração de Headers CORS
    res.setHeader('Access-Control-Allow-Credentials', true); 
    res.setHeader('Access-Control-Allow-Origin', 'https://consultadeprocessos.github.io'); 
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS'); 
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, X-Turnstile-Token'); 
  
    if (req.method === 'OPTIONS') { 
        res.status(200).end(); 
        return; 
    } 
  
    // 2. Verificação de Rate Limit
    const ipCliente = req.headers['x-forwarded-for']?.split(',')[0]?.trim()  
                   || req.headers['x-real-ip']  
                   || req.socket?.remoteAddress  
                   || 'desconhecido'; 
  
    if (!verificarRateLimit(ipCliente)) { 
        return res.status(429).json({  
            erro: "⚠️ Limite de consultas atingido. Aguarde 2 minutos e tente novamente."  
        }); 
    } 
  
    const { protocolo } = req.query; 
    if (!protocolo) { 
        return res.status(400).json({ erro: "Protocolo não informado." }); 
    } 
  
    // 3. Validação Cloudflare Turnstile
    const turnstileToken = req.headers['x-turnstile-token']; 
    if (!turnstileToken) { 
        return res.status(403).json({ erro: "Acesso negado: Validação Anti-Robô ausente." }); 
    } 
  
    const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET_KEY; 
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
            return res.status(403).json({ erro: "Falha na validação de segurança (Anti-Bot)." }); 
        } 
    } catch (e) { 
        return res.status(500).json({ erro: "Erro ao validar sistema anti-robô." }); 
    } 
  
    // 4. Conexão Supabase
    const SUPABASE_URL = process.env.SUPABASE_URL; 
    const SUPABASE_KEY = process.env.SUPABASE_KEY; 
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
  
        const [dadosSefrep, dadosSeape] = await Promise.all([resSefrep.json(), resSeape.json()]); 
  
        let todosResultados = [ 
            ...(dadosSefrep || []).map(p => ({ ...p, origem: 'SEFREP' })), 
            ...(dadosSeape || []).map(p => ({ ...p, origem: 'SEAPE' })) 
        ]; 
  
        // 5. Cálculo de Fila (Mantido Original)
        const temVtcAtivo = todosResultados.some(p => { 
            const tema = (p.tema || "").toUpperCase(); 
            const obs = (p.observacoes || "").toLowerCase(); 
            return tema.includes("VTC") && !obs.includes("finalizado") && !obs.includes("concluido") && !obs.includes("devolvido"); 
        }); 
  
        if (temVtcAtivo) { 
            const resFila = await fetch(`${SUPABASE_URL}/rest/v1/sefrep_registros?tema=ilike.*VTC*&or=(status.ilike.*lise*,status.ilike.*andamento*)&select=*`, { method: 'GET', headers: defaultHeaders }); 
            if (resFila.ok) { 
                let filaAtivaVTC = await resFila.json(); 
                filaAtivaVTC.sort((a, b) => new Date(a.data_entrada || 0) - new Date(b.data_entrada || 0)); 
  
                todosResultados = todosResultados.map(p => { 
                    const isVTC = (p.tema || "").toUpperCase().includes("VTC"); 
                    if (isVTC) { 
                        const index = filaAtivaVTC.findIndex(f => f.id === p.id); 
                        if (index >= 0) { 
                            p._posicaoFila = index + 1; 
                            p._diasEstimados = Math.max(30, 60 + Math.floor(index * 0.25)); 
                        } 
                    } 
                    return p; 
                }); 
            } 
        } 
  
        // 6. Auditoria (Silenciosa)
        const registroAuditoria = { 
            ip_hash: ipCliente.substring(0, 5) + '***', 
            protocolo_consultado: protocolo.trim().toUpperCase(), 
            resultados_encontrados: todosResultados.length, 
            data_consulta: new Date().toISOString() 
        }; 
        fetch(`${SUPABASE_URL}/rest/v1/audit_consultas`, { 
            method: 'POST', 
            headers: { ...defaultHeaders, 'Prefer': 'return=minimal' }, 
            body: JSON.stringify(registroAuditoria) 
        }).catch(() => {}); 
  
        // 7. APLICAÇÃO DA MÁSCARA DE NOME (O SEGREDO DA PRIVACIDADE)
        const resultadosSeguros = todosResultados.map(p => ({
            ...p,
            nome: aplicarMascaraNome(p.nome) // Substitui o nome real pelo mascarado
        }));
  
        return res.status(200).json({ resultados: resultadosSeguros }); 
  
    } catch (error) { 
        return res.status(500).json({ erro: "Erro na comunicação com o banco de dados." }); 
    } 
}
