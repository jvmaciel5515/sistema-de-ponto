// index.js (Versão Final Completa)

// --- DEPENDÊNCIAS ---
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const Papa = require('papaparse');

// --- CONFIGURAÇÃO INICIAL ---
const app = express();
const port = 3000;
const saltRounds = 10;

// --- SESSÃO ---
app.use(session({
    secret: 'seu-segredo-super-secreto-troque-isso',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 86400000 } // 24 horas
}));

// --- BANCO DE DADOS ---
let db;
try {
    db = new Database('./ponto.db');
    console.log('Conectado ao banco de dados com better-sqlite3.');
} catch (err) {
    console.error('### FALHA CRÍTICA AO CONECTAR NO BANCO DE DADOS ###', err);
    process.exit(1);
}

// Criação das Tabelas
const createUsersTable = `CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, email TEXT UNIQUE NOT NULL, senha TEXT NOT NULL, cargo TEXT NOT NULL DEFAULT 'bolsista')`;
const createRegistrosTable = `CREATE TABLE IF NOT EXISTS registros (id INTEGER PRIMARY KEY AUTOINCREMENT, idUsuario INTEGER NOT NULL, tipo TEXT NOT NULL CHECK(tipo IN ('entrada', 'saida')), timestamp DATETIME DEFAULT (datetime('now', 'localtime')), FOREIGN KEY (idUsuario) REFERENCES usuarios (id))`;
db.exec(createUsersTable);
db.exec(createRegistrosTable);
console.log('Tabelas "usuarios" e "registros" verificadas/criadas com sucesso.');

// Função para criar o primeiro admin se não existir
function criarPrimeiroAdmin() {
    const adminCheckStmt = db.prepare("SELECT COUNT(*) as count FROM usuarios WHERE cargo = 'admin'");
    if (adminCheckStmt.get().count === 0) {
        console.log("Nenhum admin encontrado. Criando usuário admin padrão...");
        const adminEmail = "admin@admin.com";
        const adminSenha = "admin123";
        const adminNome = "Administrador";
        const hashedSenha = bcrypt.hashSync(adminSenha, saltRounds);
        const insertStmt = db.prepare("INSERT INTO usuarios (nome, email, senha, cargo) VALUES (?, ?, ?, 'admin')");
        insertStmt.run(adminNome, adminEmail, hashedSenha);
        console.log(`Admin padrão criado com sucesso! Email: ${adminEmail}, Senha: ${adminSenha}`);
    }
}
criarPrimeiroAdmin();

// --- MIDDLEWARES ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
const authMiddleware = (req, res, next) => { (req.session && req.session.user) ? next() : res.status(401).json({ erro: 'Não autorizado' }); };
const adminOnlyMiddleware = (req, res, next) => { (req.session.user && req.session.user.cargo === 'admin') ? next() : res.status(403).json({ erro: 'Acesso negado. Somente administradores.' }); };

// --- ROTAS DE PÁGINA ---
app.get('/', (req, res) => { req.session && req.session.user ? res.redirect('/ponto.html') : res.redirect('/login.html'); });

// --- ROTAS DE API ---

// Rotas de Autenticação
app.post('/api/login', (req, res) => {
    const { email, senha } = req.body;
    const user = db.prepare('SELECT * FROM usuarios WHERE email = ?').get(email);
    if (!user) return res.status(401).json({ erro: "Email ou senha inválidos." });
    bcrypt.compare(senha, user.senha, (err, result) => {
        if (result) {
            req.session.user = { id: user.id, nome: user.nome, cargo: user.cargo };
            res.json({ mensagem: "Login bem-sucedido" });
        } else { res.status(401).json({ erro: "Email ou senha inválidos." }); }
    });
});
app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ mensagem: "Logout bem-sucedido" }); });
app.get('/api/status', authMiddleware, (req, res) => {
    const lastEntry = db.prepare("SELECT tipo FROM registros WHERE idUsuario = ? ORDER BY timestamp DESC LIMIT 1").get(req.session.user.id);
    res.json({ logado: true, usuario: req.session.user, ultimoTipo: lastEntry ? lastEntry.tipo : 'saida' });
});

// Rotas de Administração
app.post('/api/admin/criar-bolsista', authMiddleware, adminOnlyMiddleware, (req, res) => {
    const { nome, email, senha } = req.body;
    if (!nome || !email || !senha) return res.status(400).json({ erro: "Todos os campos são obrigatórios." });
    const hash = bcrypt.hashSync(senha, saltRounds);
    try {
        db.prepare("INSERT INTO usuarios (nome, email, senha, cargo) VALUES (?, ?, ?, 'bolsista')").run(nome, email, hash);
        res.status(201).json({ mensagem: `Bolsista ${nome} criado com sucesso!` });
    } catch (dbErr) { res.status(400).json({ erro: "Email já cadastrado." }); }
});
app.get('/api/admin/usuarios', authMiddleware, adminOnlyMiddleware, (req, res) => {
    try {
        const usuarios = db.prepare("SELECT id, nome, email FROM usuarios WHERE cargo = 'bolsista' ORDER BY nome ASC").all();
        res.json(usuarios);
    } catch (err) { res.status(500).json({ erro: 'Erro ao buscar usuários.' }); }
});
app.delete('/api/admin/usuario/:id', authMiddleware, adminOnlyMiddleware, (req, res) => {
    try {
        db.prepare("DELETE FROM registros WHERE idUsuario = ?").run(req.params.id);
        const info = db.prepare("DELETE FROM usuarios WHERE id = ? AND cargo = 'bolsista'").run(req.params.id);
        info.changes > 0 ? res.json({ mensagem: 'Bolsista excluído com sucesso.' }) : res.status(404).json({ erro: 'Bolsista não encontrado.' });
    } catch (err) { res.status(500).json({ erro: 'Erro ao excluir bolsista.' }); }
});
app.put('/api/admin/usuario/senha', authMiddleware, adminOnlyMiddleware, (req, res) => {
    const { id, novaSenha } = req.body;
    if (!id || !novaSenha) return res.status(400).json({ erro: 'ID e nova senha são obrigatórios.' });
    const hash = bcrypt.hashSync(novaSenha, saltRounds);
    try {
        const info = db.prepare("UPDATE usuarios SET senha = ? WHERE id = ? AND cargo = 'bolsista'").run(hash, id);
        info.changes > 0 ? res.json({ mensagem: 'Senha alterada com sucesso.' }) : res.status(404).json({ erro: 'Bolsista não encontrado.' });
    } catch (err) { res.status(500).json({ erro: 'Erro ao alterar a senha.' }); }
});
app.post('/api/admin/ajustar-ponto', authMiddleware, adminOnlyMiddleware, (req, res) => {
    const { idUsuario, dataHora, tipo } = req.body;
    if (!idUsuario || !dataHora || !tipo || !['entrada', 'saida'].includes(tipo)) return res.status(400).json({ erro: 'Dados inválidos.' });
    try {
        db.prepare("INSERT INTO registros (idUsuario, tipo, timestamp) VALUES (?, ?, ?)").run(idUsuario, tipo, dataHora);
        res.status(201).json({ mensagem: 'Registro manual adicionado com sucesso.' });
    } catch (err) { res.status(500).json({ erro: 'Erro ao inserir registro.' }); }
});
app.get('/api/admin/pendencias', authMiddleware, adminOnlyMiddleware, (req, res) => {
    try {
        const sql = `SELECT u.nome, u.id as idUsuario, DATE(r.timestamp) as dia FROM registros r JOIN usuarios u ON r.idUsuario = u.id WHERE DATE(r.timestamp) < DATE('now', 'localtime') GROUP BY u.id, DATE(r.timestamp) HAVING COUNT(r.id) % 2 != 0 AND MAX(r.timestamp) = (SELECT MAX(r2.timestamp) FROM registros r2 WHERE r2.idUsuario = r.idUsuario AND DATE(r2.timestamp) = DATE(r.timestamp) AND r2.tipo = 'entrada') ORDER BY dia DESC`;
        const pendencias = db.prepare(sql).all();
        res.json(pendencias);
    } catch (err) { console.error("Erro ao buscar pendências:", err); res.status(500).json({ erro: 'Erro ao buscar pendências.' }); }
});
app.get('/api/admin/relatorio/mensal', authMiddleware, adminOnlyMiddleware, (req, res) => {
    const { idUsuario, mes, ano } = req.query;
    if (!idUsuario || !mes || !ano) return res.status(400).send('ID do usuário, mês e ano são obrigatórios.');
    try {
        const usuario = db.prepare("SELECT nome FROM usuarios WHERE id = ?").get(idUsuario);
        if (!usuario) return res.status(404).send('Usuário não encontrado.');
        const mesFormatado = String(mes).padStart(2, '0');
        const sql = `SELECT timestamp, tipo FROM registros WHERE idUsuario = ? AND strftime('%Y-%m', timestamp) = ? ORDER BY timestamp ASC`;
        const registros = db.prepare(sql).all(idUsuario, `${ano}-${mesFormatado}`);
        let totalMilissegundos = 0;
        let ultimaEntrada = null;
        const dadosParaCsv = [];
        registros.forEach(registro => {
            const data = new Date(registro.timestamp);
            dadosParaCsv.push({ "Data": data.toLocaleDateString('pt-BR'), "Hora": data.toLocaleTimeString('pt-BR'), "Tipo": registro.tipo });
            if (registro.tipo === 'entrada') {
                if (!ultimaEntrada) ultimaEntrada = data;
            } else if (registro.tipo === 'saida' && ultimaEntrada) {
                totalMilissegundos += data - ultimaEntrada;
                ultimaEntrada = null;
            }
        });
        const horas = Math.floor(totalMilissegundos / 3600000);
        const minutos = Math.floor((totalMilissegundos % 3600000) / 60000);
        dadosParaCsv.push({}, { "Data": "TOTAL DE HORAS NO MÊS" }, { "Data": "Horas", "Hora": "Minutos" }, { "Data": horas, "Hora": minutos });
        const csv = Papa.unparse(dadosParaCsv);
        const nomeArquivo = `relatorio_${usuario.nome.replace(/\s+/g, '_')}_${mes}_${ano}.csv`;
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(nomeArquivo)}`);
        res.status(200).end(csv);
    } catch (err) { console.error("Erro ao gerar relatório:", err); res.status(500).send("Erro interno ao gerar o relatório."); }
});

// --- ROTAS DO PONTO ---
app.post('/api/ponto', authMiddleware, (req, res) => {
    const idUsuario = req.session.user.id;
    const lastEntry = db.prepare("SELECT tipo FROM registros WHERE idUsuario = ? ORDER BY timestamp DESC LIMIT 1").get(idUsuario);
    const novoTipo = (!lastEntry || lastEntry.tipo === 'saida') ? 'entrada' : 'saida';
    db.prepare("INSERT INTO registros (idUsuario, tipo) VALUES (?, ?)").run(idUsuario, novoTipo);
    res.status(201).json({ mensagem: `Registro de '${novoTipo}' efetuado com sucesso.`, novoTipo: novoTipo });
});
app.get('/api/registros', authMiddleware, (req, res) => {
    const registros = db.prepare("SELECT tipo, timestamp FROM registros WHERE idUsuario = ? ORDER BY timestamp DESC").all(req.session.user.id);
    res.json(registros);
});
app.get('/api/relatorio/hoje', authMiddleware, (req, res) => {
    const registrosDoDia = db.prepare("SELECT timestamp, tipo FROM registros WHERE idUsuario = ? AND date(timestamp) = date('now', 'localtime') ORDER BY timestamp ASC").all(req.session.user.id);
    let totalMilissegundos = 0;
    let ultimaEntrada = null;
    registrosDoDia.forEach(registro => {
        if (registro.tipo === 'entrada') { if (!ultimaEntrada) ultimaEntrada = new Date(registro.timestamp); }
        else if (registro.tipo === 'saida' && ultimaEntrada) { totalMilissegundos += new Date(registro.timestamp) - ultimaEntrada; ultimaEntrada = null; }
    });
    if (ultimaEntrada) { totalMilissegundos += new Date() - ultimaEntrada; }
    const horas = Math.floor(totalMilissegundos / 3600000);
    const minutos = Math.floor((totalMilissegundos % 3600000) / 60000);
    res.json({ formatado: `${String(horas).padStart(2, '0')}:${String(minutos).padStart(2, '0')}` });
});

// --- INICIAR SERVIDOR ---
app.listen(port, () => { console.log(`Servidor rodando. Acesse http://localhost:${port}`); });