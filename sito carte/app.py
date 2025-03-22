from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
import sqlite3
import os
import secrets
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import hashlib
import bcrypt

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True

# Configurazione cartelle
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads')
DATABASE_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Crea le cartelle se non esistono
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DATABASE_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Funzione per verificare l'estensione del file
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Funzione per inizializzare il database
def init_db():
    conn = sqlite3.connect(os.path.join(DATABASE_FOLDER, 'pokemon_cards.db'))
    cursor = conn.cursor()
    
    # Tabella utenti
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        verification_code TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Tabella categorie (espansioni)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Tabella prodotti (carte)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        code TEXT UNIQUE NOT NULL,
        price REAL NOT NULL,
        image_path TEXT,
        category_id INTEGER,
        additional_info TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (category_id) REFERENCES categories (id)
    )
    ''')
    
    # Controlla se esiste già un utente admin, altrimenti crealo
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        # Hash the password using bcrypt and store as bytes
        hashed_password = bcrypt.hashpw('PolloSaltato99'.encode(), bcrypt.gensalt())
        # Converti in stringa per evitare problemi di compatibilità con SQLite
        hashed_password_str = hashed_password.decode('utf-8')
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', hashed_password_str))
        print("Utente admin creato con password: PolloSaltato99")
    
    conn.commit()
    conn.close()

# Inizializza il database all'avvio dell'applicazione
init_db()

# Middleware per verificare se l'utente è loggato
def login_required(f):
    def decorated_function(*args, **kwargs):
        print(f"Checking login requirement, session: {session}")
        if 'user_id' not in session:
            flash('Devi effettuare il login per accedere a questa pagina', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Rotte per il frontend pubblico
@app.route('/')
def index():
    conn = sqlite3.connect(os.path.join(DATABASE_FOLDER, 'pokemon_cards.db'))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Ottieni tutte le categorie
    cursor.execute("SELECT * FROM categories ORDER BY name")
    categories = cursor.fetchall()
    
    # Ottieni tutti i prodotti
    cursor.execute("SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id ORDER BY p.name")
    products = cursor.fetchall()
    
    conn.close()
    return render_template('index.html', categories=categories, products=products)

@app.route('/category/<int:category_id>')
def category(category_id):
    conn = sqlite3.connect(os.path.join(DATABASE_FOLDER, 'pokemon_cards.db'))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Ottieni la categoria
    cursor.execute("SELECT * FROM categories WHERE id = ?", (category_id,))
    category = cursor.fetchone()
    
    if not category:
        conn.close()
        flash('Categoria non trovata', 'danger')
        return redirect(url_for('index'))
    
    # Ottieni i prodotti della categoria
    cursor.execute("SELECT * FROM products WHERE category_id = ? ORDER BY name", (category_id,))
    products = cursor.fetchall()
    
    conn.close()
    return render_template('category.html', category=category, products=products)

class SecureLogin:
    def __init__(self):
        self.stored_hashed_pin = "ae4d4c8c3da2a3a23c23f2a357deb8a99b11512b5226aa7bd2ea3a67d0402428"  
    
    def hash_pin(self, pin):
        return hashlib.sha256(pin.encode()).hexdigest()
    
    def login(self, input_pin):
        if self.hash_pin(input_pin) == self.stored_hashed_pin:
            print("Login riuscito!")
            return True
        else:
            print("PIN errato. Accesso negato.")
            return False

# Rotte per l'autenticazione
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Debug: Check if already logged in
    if 'user_id' in session:
        print(f"User already logged in: {session}")
        return redirect(url_for('admin_dashboard'))
        
    if request.method == 'POST':
        input_pin = request.form['verification_code']
        
        print(f"Login attempt with PIN: {input_pin}")
        
        # Use SecureLogin class for PIN verification
        login_system = SecureLogin()
        if login_system.login(input_pin):
            # Clear and set session
            session.clear()
            session['user_id'] = 1  # Assuming admin user_id is 1
            session['username'] = 'admin'
            
            # Debug session after setting
            print(f"Session after login: {session}")
            
            flash('Login effettuato con successo', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('PIN errato. Accesso negato.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logout effettuato con successo', 'success')
    return redirect(url_for('index'))

# Rotte per l'amministrazione
@app.route('/admin')
@login_required
def admin_dashboard():
    # Add a debug print to check session
    print(f"Session data: {session}")
    
    conn = sqlite3.connect(os.path.join(DATABASE_FOLDER, 'pokemon_cards.db'))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Ottieni il conteggio dei prodotti
    cursor.execute("SELECT COUNT(*) as count FROM products")
    product_count = cursor.fetchone()['count']
    
    # Ottieni il conteggio delle categorie
    cursor.execute("SELECT COUNT(*) as count FROM categories")
    category_count = cursor.fetchone()['count']
    
    conn.close()
    # Pass the current year to the template
    return render_template('admin/dashboard.html', product_count=product_count, category_count=category_count, now=datetime.now())

# Gestione prodotti
@app.route('/admin/products')
@login_required
def admin_products():
    conn = sqlite3.connect(os.path.join(DATABASE_FOLDER, 'pokemon_cards.db'))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Ottieni tutti i prodotti con il nome della categoria
    cursor.execute("SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id ORDER BY p.name")
    products = cursor.fetchall()
    
    conn.close()
    return render_template('admin/products.html', products=products)

@app.route('/admin/products/add', methods=['GET', 'POST'])
@login_required
def admin_add_product():
    if request.method == 'POST':
        name = request.form['name']
        code = request.form['code']
        price = float(request.form['price'])
        category_id = request.form['category_id'] if request.form['category_id'] else None
        additional_info = request.form['additional_info']
        
        # Gestione dell'immagine
        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Aggiungi timestamp al nome del file per evitare duplicati
                filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                image_path = f"uploads/{filename}"
        
        conn = sqlite3.connect(os.path.join(DATABASE_FOLDER, 'pokemon_cards.db'))
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO products (name, code, price, image_path, category_id, additional_info)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (name, code, price, image_path, category_id, additional_info))
            conn.commit()
            flash('Prodotto aggiunto con successo', 'success')
            return redirect(url_for('admin_products'))
        except sqlite3.IntegrityError:
            flash('Errore: Il codice prodotto deve essere unico', 'danger')
        finally:
            conn.close()
    
    # Ottieni tutte le categorie per il form
    conn = sqlite3.connect(os.path.join(DATABASE_FOLDER, 'pokemon_cards.db'))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM categories ORDER BY name")
    categories = cursor.fetchall()
    conn.close()
    
    return render_template('admin/add_product.html', categories=categories)

@app.route('/admin/products/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_product(product_id):
    conn = sqlite3.connect(os.path.join(DATABASE_FOLDER, 'pokemon_cards.db'))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Ottieni il prodotto
    cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        conn.close()
        flash('Prodotto non trovato', 'danger')
        return redirect(url_for('admin_products'))
    
    if request.method == 'POST':
        name = request.form['name']
        code = request.form['code']
        price = float(request.form['price'])
        category_id = request.form['category_id'] if request.form['category_id'] else None
        additional_info = request.form['additional_info']
        
        # Gestione dell'immagine
        image_path = product['image_path']
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Aggiungi timestamp al nome del file per evitare duplicati
                filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                # Elimina la vecchia immagine se esiste
                if product['image_path']:
                    old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], product['image_path'].split('/')[-1])
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                
                image_path = f"uploads/{filename}"
        
        try:
            cursor.execute("""
                UPDATE products
                SET name = ?, code = ?, price = ?, image_path = ?, category_id = ?, additional_info = ?
                WHERE id = ?
            """, (name, code, price, image_path, category_id, additional_info, product_id))
            conn.commit()
            flash('Prodotto aggiornato con successo', 'success')
            return redirect(url_for('admin_products'))
        except sqlite3.IntegrityError:
            flash('Errore: Il codice prodotto deve essere unico', 'danger')
    
    # Ottieni tutte le categorie per il form
    cursor.execute("SELECT * FROM categories ORDER BY name")
    categories = cursor.fetchall()
    
    conn.close()
    return render_template('admin/edit_product.html', product=product, categories=categories)

@app.route('/admin/products/delete/<int:product_id>', methods=['POST'])
@login_required
def admin_delete_product(product_id):
    conn = sqlite3.connect(os.path.join(DATABASE_FOLDER, 'pokemon_cards.db'))
    cursor = conn.cursor()
    
    # Ottieni il prodotto per eliminare l'immagine associata
    cursor.execute("SELECT image_path FROM products WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if product and product[0]:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], product[0].split('/')[-1])
        if os.path.exists(image_path):
            os.remove(image_path)
    
    # Elimina il prodotto
    cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
    conn.commit()
    conn.close()
    
    flash('Prodotto eliminato con successo', 'success')
    return redirect(url_for('admin_products'))

# Gestione categorie
@app.route('/admin/categories')
@login_required
def admin_categories():
    conn = sqlite3.connect(os.path.join(DATABASE_FOLDER, 'pokemon_cards.db'))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Ottieni tutte le categorie con il conteggio dei prodotti
    cursor.execute("""
        SELECT c.*, COUNT(p.id) as product_count
        FROM categories c
        LEFT JOIN products p ON c.id = p.category_id
        GROUP BY c.id
        ORDER BY c.name
    """)
    categories = cursor.fetchall()
    
    conn.close()
    return render_template('admin/categories.html', categories=categories)

@app.route('/admin/categories/add', methods=['GET', 'POST'])
@login_required
def admin_add_category():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        
        conn = sqlite3.connect(os.path.join(DATABASE_FOLDER, 'pokemon_cards.db'))
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO categories (name, description)
                VALUES (?, ?)
            """, (name, description))
            conn.commit()
            flash('Categoria aggiunta con successo', 'success')
            return redirect(url_for('admin_categories'))
        except sqlite3.IntegrityError:
            flash('Errore: Il nome della categoria deve essere unico', 'danger')
        finally:
            conn.close()
    
    return render_template('admin/add_category.html')

@app.route('/admin/categories/edit/<int:category_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_category(category_id):
    conn = sqlite3.connect(os.path.join(DATABASE_FOLDER, 'pokemon_cards.db'))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Ottieni la categoria
    cursor.execute("SELECT * FROM categories WHERE id = ?", (category_id,))
    category = cursor.fetchone()
    
    if not category:
        conn.close()
        flash('Categoria non trovata', 'danger')
        return redirect(url_for('admin_categories'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        
        try:
            cursor.execute("""
                UPDATE categories
                SET name = ?, description = ?
                WHERE id = ?
            """, (name, description, category_id))
            conn.commit()
            flash('Categoria aggiornata con successo', 'success')
            return redirect(url_for('admin_categories'))
        except sqlite3.IntegrityError:
            flash('Errore: Il nome della categoria deve essere unico', 'danger')
    
    conn.close()
    return render_template('admin/edit_category.html', category=category)

@app.route('/admin/categories/delete/<int:category_id>', methods=['POST'])
@login_required
def admin_delete_category(category_id):
    conn = sqlite3.connect(os.path.join(DATABASE_FOLDER, 'pokemon_cards.db'))
    cursor = conn.cursor()
    
    # Verifica se ci sono prodotti associati a questa categoria
    cursor.execute("SELECT COUNT(*) FROM products WHERE category_id = ?", (category_id,))
    count = cursor.fetchone()[0]
    
    if count > 0:
        flash('Impossibile eliminare la categoria: ci sono prodotti associati', 'danger')
    else:
        # Elimina la categoria
        cursor.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        conn.commit()
        flash('Categoria eliminata con successo', 'success')
    
    conn.close()
    return redirect(url_for('admin_categories'))

# API per ottenere l'immagine del prodotto
@app.route('/api/product/image/<int:product_id>')
def get_product_image(product_id):
    conn = sqlite3.connect(os.path.join(DATABASE_FOLDER, 'pokemon_cards.db'))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT image_path FROM products WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    conn.close()
    
    if product and product['image_path']:
        return jsonify({'image_path': product['image_path']})
    else:
        return jsonify({'error': 'Immagine non trovata'}), 404

# Route per la ricerca
@app.route('/search')
def search():
    query = request.args.get('query', '')
    min_price = request.args.get('min_price', '')
    max_price = request.args.get('max_price', '')
    sort_by = request.args.get('sort_by', 'name')
    category_id = request.args.get('category_id', '')
    
    # Permetti l'ordinamento anche senza filtri di ricerca
    # if not query and not min_price and not max_price and not category_id:
    #     flash('Inserisci un termine di ricerca o un filtro di prezzo', 'warning')
    #     return redirect(url_for('index'))
    
    conn = sqlite3.connect(os.path.join(DATABASE_FOLDER, 'pokemon_cards.db'))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Ottieni tutte le categorie per il form di filtro
    cursor.execute("SELECT * FROM categories ORDER BY name")
    categories = cursor.fetchall()
    
    # Costruisci la query SQL in base ai filtri
    sql_query = """
        SELECT p.*, c.name as category_name 
        FROM products p 
        LEFT JOIN categories c ON p.category_id = c.id 
        WHERE 1=1
    """
    params = []
    
    # Aggiungi filtro per nome o codice
    if query:
        sql_query += " AND (p.name LIKE ? OR p.code LIKE ?)"
        params.extend([f'%{query}%', f'%{query}%'])
    
    # Aggiungi filtro per categoria
    if category_id and category_id.isdigit():
        sql_query += " AND p.category_id = ?"
        params.append(int(category_id))
    
    # Aggiungi filtro per prezzo minimo
    if min_price and min_price.replace('.', '', 1).isdigit():
        sql_query += " AND p.price >= ?"
        params.append(float(min_price))
    
    # Aggiungi filtro per prezzo massimo
    if max_price and max_price.replace('.', '', 1).isdigit():
        sql_query += " AND p.price <= ?"
        params.append(float(max_price))
    
    # Aggiungi ordinamento
    if sort_by == 'price_asc':
        sql_query += " ORDER BY p.price ASC"
    elif sort_by == 'price_desc':
        sql_query += " ORDER BY p.price DESC"
    else:
        sql_query += " ORDER BY p.name"
    
    cursor.execute(sql_query, params)
    products = cursor.fetchall()
    conn.close()
    
    return render_template('search_results.html', products=products, categories=categories, query=query, min_price=min_price, max_price=max_price, sort_by=sort_by, category_id=category_id)

if __name__ == '__main__':
    app.run(debug=True)