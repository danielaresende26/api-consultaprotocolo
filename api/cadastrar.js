// c:\Users\daniela.resende\Desktop\tela-de-login-main\api-consultaprotocolo\api\cadastrar.js
const { createClient } = require('@supabase/supabase-js');

module.exports = async (req, res) => {
    // 1. Configurar CORS (Permitir apenas o domínio do GitHub Pages)
    res.setHeader('Access-Control-Allow-Origin', 'https://uresuzano.github.io');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ erro: 'Método não permitido' });
    }

    try {
        const { SUPABASE_URL, SUPABASE_KEY } = process.env;
        const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

        // 2. Validar Autenticação (JWT do Supabase Auth enviado no header)
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ erro: 'Não autorizado: Token ausente' });
        }

        const token = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authError } = await supabase.auth.getUser(token);

        if (authError || !user) {
            return res.status(401).json({ erro: 'Sessão inválida ou expirada' });
        }

        // 3. Receber e Validar Dados
        const { tabela, dados } = req.body;
        if (!tabela || !dados || !['sefrep_registros', 'seape_registros'].includes(tabela)) {
            return res.status(400).json({ erro: 'Dados ou tabela inválidos' });
        }

        // 4. Inserir no Banco
        const { data, error } = await supabase
            .from(tabela)
            .insert([dados])
            .select();

        if (error) throw error;

        // 5. Audit Log (Opcional, mas recomendado para LGPD)
        await supabase.from('auditoria_consultas').insert([{
            protocolo: dados.protocolo || 'CADASTRO',
            ip_origem: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
            detalhes: `Admin ${user.email} cadastrou registro em ${tabela}`
        }]);

        return res.status(201).json({ sucesso: true, data });

    } catch (error) {
        console.error('Erro no cadastro:', error);
        return res.status(500).json({ erro: 'Erro interno ao processar cadastro' });
    }
};
