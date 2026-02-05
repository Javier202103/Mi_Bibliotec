const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();

// Middlewares importantes (deben ir ANTES de las rutas)
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));  // Necesario para campos texto en multipart

// Conexión a PostgreSQL (usa la variable de entorno de Render)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Carpeta para guardar archivos subidos
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// Configuración de multer (almacenamiento en disco)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage });

// Ruta para registro (signup)
app.post('/api/signup', async (req, res) => {
    const { nombre, email, password } = req.body;

    if (!nombre || !email || !password) {
        return res.status(400).json({ error: 'Faltan campos obligatorios' });
    }

    try {
        const hashedPass = await bcrypt.hash(password, 10);

        await pool.query(
            'INSERT INTO usuarios (nombre, email, password) VALUES ($1, $2, $3)',
            [nombre, email, hashedPass]
        );

        res.status(201).json({ message: 'Usuario creado con éxito' });
    } catch (err) {
        console.error('Error al crear usuario:', err);
        if (err.code === '23505') {
            return res.status(409).json({ error: 'El email ya está registrado' });
        }
        res.status(500).json({ error: 'Error interno al crear el usuario' });
    }
});

// Ruta para login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        const token = jwt.sign(
            { id: user.id, es_admin: user.es_admin || false },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ token, es_admin: user.es_admin || false });
    } catch (err) {
        console.error('Error en login:', err);
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// Middleware para verificar token
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Token requerido' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = user;
        next();
    });
};

// Agregar libro (admin)
app.post('/api/libros', verifyToken, upload.fields([{ name: 'imagen', maxCount: 1 }, { name: 'pdf', maxCount: 1 }]), async (req, res) => {
    const { titulo, autor, categoria } = req.body;
    const imagen = req.files['imagen'] ? req.files['imagen'][0].filename : null;
    const pdf = req.files['pdf'] ? req.files['pdf'][0].filename : null;

    if (!titulo || !autor || !categoria || !imagen || !pdf) {
        return res.status(400).json({ error: 'Faltan campos obligatorios' });
    }

    if (!req.user.es_admin) {
        return res.status(403).json({ error: 'Solo administradores pueden agregar libros' });
    }

    try {
        await pool.query(
            'INSERT INTO libros (titulo, autor, categoria, imagen_url, pdf_url) VALUES ($1, $2, $3, $4, $5)',
            [titulo, autor, categoria, imagen, pdf]
        );
        res.json({ message: 'Libro agregado' });
    } catch (err) {
        console.error('Error al agregar libro:', err);
        res.status(500).json({ error: 'Error al agregar libro' });
    }
});

// Borrar libro (admin)
app.delete('/api/libros/:id', verifyToken, async (req, res) => {
    try {
        if (!req.user.es_admin) {
            return res.status(403).json({ error: 'Solo administradores pueden borrar libros' });
        }

        const result = await pool.query('DELETE FROM libros WHERE id = $1 RETURNING *', [req.params.id]);

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Libro no encontrado' });
        }

        res.json({ message: 'Libro borrado correctamente' });
    } catch (err) {
        console.error('Error al borrar libro:', err);
        res.status(500).json({ error: 'Error al borrar' });
    }
});

// Obtener todos los libros
app.get('/api/libros', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM libros ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        console.error('Error al obtener libros:', err);
        res.status(500).json({ error: 'Error al cargar catálogo' });
    }
});

// Endpoint para categorías únicas
app.get('/api/categorias', async (req, res) => {
    try {
        const result = await pool.query('SELECT DISTINCT categoria FROM libros WHERE categoria IS NOT NULL AND categoria != \'\' ORDER BY categoria');
        const categorias = result.rows.map(row => row.categoria);
        res.json(categorias);
    } catch (err) {
        console.error('Error al obtener categorías:', err);
        res.status(500).json({ error: 'Error al obtener categorías' });
    }
});

// Servir archivos subidos (imágenes y PDFs)
app.use('/uploads', express.static(uploadDir));

// Servir archivos estáticos del frontend (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, '.')));

// Ruta principal: enviar index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Iniciar servidor con puerto dinámico para Render
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Servidor corriendo en puerto ${port}`);
});