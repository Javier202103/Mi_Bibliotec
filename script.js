// Esperamos a que la página cargue completamente
document.addEventListener('DOMContentLoaded', () => {
    console.log('Página cargada - conectando eventos...');

    // Variables globales
    const catalogContainer = document.getElementById('catalog-container');
    const registerModal = document.getElementById('register-modal');
    const loginModal = document.getElementById('login-modal');
    const btnRegister = document.getElementById('btn-register');
    const btnLogin = document.getElementById('btn-login');
    const closeRegister = document.querySelector('#register-modal .close');
    const closeLogin = document.querySelector('#login-modal .close');
    const registerForm = document.getElementById('register-form');
    const loginForm = document.getElementById('login-form');
    const addBookForm = document.getElementById('add-book-form');
    const adminSection = document.getElementById('admin-section');
    const searchInput = document.getElementById('search-input');

    let currentToken = localStorage.getItem('token') || null;
    let isAdmin = localStorage.getItem('isAdmin') === 'true';
    let currentCategory = 'todas';  // Filtro de categoría por defecto

    // Funciones de modal
    function openRegister() { 
        if (registerModal) {
            registerModal.style.display = 'block'; 
            document.body.classList.add('modal-open'); 
        }
    }
    function closeRegisterModal() { 
        if (registerModal) {
            registerModal.style.display = 'none'; 
            document.body.classList.remove('modal-open'); 
        }
    }
    function openLogin() { 
        if (loginModal) {
            loginModal.style.display = 'block'; 
            document.body.classList.add('modal-open'); 
        }
    }
    function closeLoginModal() { 
        if (loginModal) {
            loginModal.style.display = 'none'; 
            document.body.classList.remove('modal-open'); 
        }
    }

    // Conectar botones solo si existen
    if (btnRegister) btnRegister.onclick = openRegister;
    if (btnLogin) btnLogin.onclick = openLogin;
    if (closeRegister) closeRegister.onclick = closeRegisterModal;
    if (closeLogin) closeLogin.onclick = closeLoginModal;

    window.onclick = (e) => {
        if (e.target === registerModal) closeRegisterModal();
        if (e.target === loginModal) closeLoginModal();
    };

    // Cargar y renderizar libros (con filtro de búsqueda y categoría)
    async function fetchAndRenderBooks(searchTerm = '', category = 'todas') {
        try {
            const res = await fetch('https://mi-biblioteca.onrender.com/api/libros');
            if (!res.ok) throw new Error('Error al cargar libros');
            
            let books = await res.json();

            // Filtro por categoría
            if (category !== 'todas') {
                books = books.filter(b => b.categoria && b.categoria.toLowerCase() === category.toLowerCase());
            }

            // Filtro por búsqueda
            if (searchTerm) {
                const term = searchTerm.toLowerCase().trim();
                books = books.filter(b => 
                    b.titulo.toLowerCase().includes(term) ||
                    b.autor.toLowerCase().includes(term) ||
                    b.categoria.toLowerCase().includes(term)
                );
            }

            catalogContainer.innerHTML = '';
            if (books.length === 0) {
                catalogContainer.innerHTML = '<p style="text-align:center; color:#666; padding:40px;">No se encontraron libros.</p>';
                return;
            }

            books.forEach(book => {
                const card = document.createElement('div');
                card.className = 'book-card';
                card.innerHTML = `
                    <div class="book-cover">
                        <img src="https://mi-biblioteca.onrender.com/uploads/${book.imagen_url || 'placeholder.jpg'}" alt="${book.titulo}" onerror="this.src='https://via.placeholder.com/200x280?text=Libro'">
                    </div>
                    <div class="book-info">
                        <div class="book-title"><strong>${book.titulo}</strong></div>
                        <div class="book-author">${book.autor}</div>
                        <div class="book-category">${book.categoria}</div>
                        ${currentToken ? `<button class="btn-primary" onclick="openPDF('${book.pdf_url || ''}')">Leer PDF</button>` : ''}
                        ${isAdmin ? `<button class="btn-borrar" onclick="deleteBook(${book.id})">Borrar</button>` : ''}
                        ${isAdmin ? `<button class="btn-prestar" onclick="prestarBook(${book.id})">Prestar</button>` : ''}
                    </div>
                `;
                catalogContainer.appendChild(card);
            });
        } catch (err) {
            console.error('Error cargando libros:', err);
            catalogContainer.innerHTML = '<p style="color:red; text-align:center;">Error al cargar los libros</p>';
        }
    }

    // Cargar categorías dinámicas
    async function cargarCategorias() {
        try {
            const res = await fetch('https://mi-biblioteca.onrender.com/api/categorias');
            if (!res.ok) throw new Error('Error al cargar categorías');

            const categorias = await res.json();

            const menu = document.getElementById('categorias-menu');
            if (!menu) return;

            // Limpiar menú (excepto "Todas")
            menu.innerHTML = '<li><a href="#" data-categoria="todas" class="categoria-link">Todas</a></li>';

            // Agregar categorías dinámicas
            categorias.forEach(cat => {
                if (cat && cat.trim() !== '') {
                    const li = document.createElement('li');
                    li.innerHTML = `<a href="#" data-categoria="${cat}" class="categoria-link">${cat}</a>`;
                    menu.appendChild(li);
                }
            });

            // Asignar eventos a los links
            asignarEventosCategorias();
        } catch (err) {
            console.error('Error cargando categorías:', err);
        }
    }

    // Asignar eventos a links de categorías
    function asignarEventosCategorias() {
        document.querySelectorAll('.categoria-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                currentCategory = link.getAttribute('data-categoria');
                document.querySelector('.dropbtn').innerHTML = `${link.textContent} <i class="fas fa-chevron-down"></i>`;
                fetchAndRenderBooks(searchInput.value, currentCategory);
            });
        });
    }

    window.openPDF = function(pdfUrl) {
        if (pdfUrl) {
            window.open(`https://mi-biblioteca.onrender.com/uploads/${pdfUrl}`, '_blank');
        } else {
            alert('No hay PDF disponible para este libro');
        }
    };

    window.deleteBook = async function(id) {
        if (!confirm('¿Seguro que quieres borrar este libro?')) return;
        
        try {
            const res = await fetch(`https://mi-biblioteca.onrender.com/api/libros/${id}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${currentToken}` }
            });
            
            if (res.ok) {
                alert('Libro borrado correctamente');
                fetchAndRenderBooks(searchInput.value, currentCategory);
                cargarCategorias();  // Recarga categorías por si borró la última de una cat
            } else {
                const data = await res.json();
                alert(data.error || 'No se pudo borrar el libro');
            }
        } catch (err) {
            console.error(err);
            alert('Error de conexión al intentar borrar');
        }
    };

    window.prestarBook = async function(id) {
        const email = prompt('Ingrese el email del usuario a quien prestar el libro:');
        if (!email || !email.trim()) {
            alert('Operación cancelada');
            return;
        }

        try {
            const res = await fetch('https://mi-biblioteca.onrender.com/api/prestamos', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${currentToken}`
                },
                body: JSON.stringify({ libro_id: id, usuario_email: email.trim() })
            });

            const data = await res.json();

            if (res.ok) {
                alert('Libro prestado exitosamente');
                fetchAndRenderBooks(searchInput.value, currentCategory);
            } else {
                alert(data.error || 'No se pudo realizar el préstamo');
            }
        } catch (err) {
            console.error(err);
            alert('Error de conexión al intentar prestar');
        }
    };

    // Registro
    registerForm?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const data = {
            nombre: document.getElementById('reg-name').value.trim(),
            email: document.getElementById('reg-email').value.trim(),
            password: document.getElementById('reg-password').value
        };
        try {
            const res = await fetch('https://mi-biblioteca.onrender.com/api/signup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            const result = await res.json();
            if (res.ok) {
                alert('Cuenta creada. Inicia sesión.');
                closeRegisterModal();
                openLogin();
            } else {
                alert(result.error || 'Error al registrar');
            }
        } catch (err) {
            alert('Error de conexión');
        }
    });

    // Login
    loginForm?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const data = {
            email: document.getElementById('login-email').value.trim(),
            password: document.getElementById('login-password').value
        };
        try {
            const res = await fetch('https://mi-biblioteca.onrender.com/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            const result = await res.json();
            if (res.ok) {
                currentToken = result.token;
                isAdmin = result.es_admin === true;
                localStorage.setItem('token', currentToken);
                localStorage.setItem('isAdmin', isAdmin);
                alert('Sesión iniciada');
                closeLoginModal();
                if (isAdmin) adminSection.style.display = 'block';
                btnLogin.textContent = 'Cerrar Sesión';
                btnLogin.onclick = () => {
                    localStorage.clear();
                    location.reload();
                };
                fetchAndRenderBooks(searchInput.value, currentCategory);
            } else {
                alert(result.error || 'Credenciales inválidas');
            }
        } catch (err) {
            alert('Error de conexión');
        }
    });

    // Agregar libro
    addBookForm?.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (!currentToken || !isAdmin) return alert('Solo admins');
        const formData = new FormData(addBookForm);
        try {
            const res = await fetch('https://mi-biblioteca.onrender.com/api/libros', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${currentToken}` },
                body: formData
            });
            if (res.ok) {
                alert('Libro agregado');
                addBookForm.reset();
                fetchAndRenderBooks(searchInput.value, currentCategory);
                cargarCategorias();  // Recarga el menú con posible nueva categoría
            } else {
                alert('Error al agregar');
            }
        } catch (err) {
            alert('Error: ' + err.message);
        }
    });

    // Buscador
    searchInput?.addEventListener('input', (e) => fetchAndRenderBooks(e.target.value, currentCategory));

    // Cargar al inicio
    fetchAndRenderBooks('', currentCategory);
    cargarCategorias();  // Carga categorías dinámicas
});