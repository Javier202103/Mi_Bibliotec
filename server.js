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

// Conexión a PostgreSQL (cambia la contraseña si es diferente)
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'mi_biblioteca',
    password: '123456',  // ← CAMBIA ESTO si tu contraseña es otra
    port: 5432,
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

// Ruta para registro (signup) - versión corregida sin 'titulo'
app.post('/api/signup', async (req, res) => {
    const { nombre, email, password } = req.body;

    if (!nombre || !email || !password) {
        return res.status(400).json({ error: 'Faltan campos obligatorios: nombre, email o password' });
    }

    try {
        const hashedPass = await bcrypt.hash(password, 10);

        await pool.query(
            'INSERT INTO usuarios (nombre, email, password) VALUES ($1, $2, $3)',
            [nombre, email, hashedPass]
        );

        res.status(201).json({ message: 'Usuario creado con éxito' });
    } catch (err) {
        console.error('Error completo al crear usuario:', err);

        // Error de email duplicado (código PostgreSQL 23505)
        if (err.code === '23505') {
            return res.status(409).json({ error: 'El email ya está registrado' });
        }

        // Otros errores
        res.status(500).json({ error: 'Error interno al crear el usuario', details: err.message });
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
            'secret',  // Cambia esto por una clave más segura en producción
            { expiresIn: '24h' }
        );

        res.json({ token, es_admin: user.es_admin || false });
    } catch (err) {
        console.error('Error en login:', err);
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// Middleware para verificar token (auth)
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Token requerido' });

    jwt.verify(token, 'secret', (err, user) => {
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
    console.log('Intento de borrar libro ID:', req.params.id, 'por usuario:', req.user);

    try {
        if (!req.user.es_admin) {
            console.log('Usuario no es admin');
            return res.status(403).json({ error: 'Solo administradores pueden borrar libros' });
        }

        const libroId = req.params.id;

        const result = await pool.query('DELETE FROM libros WHERE id = $1 RETURNING *', [libroId]);

        if (result.rowCount === 0) {
            console.log('Libro no encontrado, ID:', libroId);
            return res.status(404).json({ error: 'Libro no encontrado' });
        }

        console.log('Libro borrado con éxito, ID:', libroId);
        res.json({ message: 'Libro borrado correctamente', libroId });
    } catch (err) {
        console.error('Error al borrar libro:', err.stack);
        res.status(500).json({ error: 'Error al borrar el libro', details: err.message });
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

// Registrar préstamo
app.post('/api/prestamos', verifyToken, async (req, res) => {
    const { libro_id, tiempo_lectura } = req.body;
    const usuario_id = req.user.id;

    try {
        await pool.query(
            'INSERT INTO prestamos (libro_id, usuario_id, tiempo_lectura) VALUES ($1, $2, $3)',
            [libro_id, usuario_id, tiempo_lectura]
        );
        res.json({ message: 'Préstamo registrado' });
    } catch (err) {
        console.error('Error en préstamo:', err);
        res.status(500).json({ error: 'Error al registrar préstamo' });
    }
});

// Obtener préstamos del usuario
app.get('/api/prestamos', verifyToken, async (req, res) => {
    const usuario_id = req.user.id;
    try {
        const result = await pool.query(`
            SELECT p.*, l.titulo, l.autor, l.imagen_url, l.pdf_url
            FROM prestamos p
            JOIN libros l ON p.libro_id = l.id
            WHERE p.usuario_id = $1
            ORDER BY p.fecha_prestamo DESC
        `, [usuario_id]);
        res.json(result.rows);
    } catch (err) {
        console.error('Error al obtener préstamos:', err);
        res.status(500).json({ error: 'Error al cargar préstamos' });
    }
});

// Descargar PDF (requiere login)
app.get('/api/download/:filename', verifyToken, (req, res) => {
    const filePath = path.join(uploadDir, req.params.filename);
    console.log('Intentando descargar:', filePath);
    if (fs.existsSync(filePath)) {
        res.download(filePath);
    } else {
        res.status(404).json({ error: 'Archivo no encontrado' });
    }
});

// Servir archivos subidos (imágenes y PDFs)
app.use('/uploads', express.static(uploadDir));

// Nuevo endpoint para categorías únicas
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

// Iniciar servidor
app.listen(3000, () => {
    console.log('Servidor corriendo en https://mi-biblioteca.onrender.com');
});