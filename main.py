import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import sqlite3
from tkinter import font
from tkinter import PhotoImage
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
import base64
import os
import json


# Clave de cifrado
KEY_FILE = 'encryption_key.json'


def save_key(key):
    with open(KEY_FILE, 'w') as f:
        json.dump(key.decode('latin-1'), f)


def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'r') as f:
            key_data = json.load(f)
            return key_data.encode('latin-1')
    else:
        return None


# Crear la base de datos y la tabla para almacenar las contraseñas
conn = sqlite3.connect('db/passwords.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                  (id INTEGER PRIMARY KEY AUTOINCREMENT,
                   application TEXT,
                   category TEXT,
                   username TEXT,
                   email TEXT,
                   password TEXT)''')
conn.commit()


# Función para encriptar la contraseña utilizando AES
def encrypt_password(password):
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(password.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    encrypted_password = base64.b64encode(cipher_text).decode('utf-8')
    return iv + encrypted_password


# Función para desencriptar la contraseña
def decrypt_password(encrypted_password):
    iv = base64.b64decode(encrypted_password[:24])
    cipher_text = base64.b64decode(encrypted_password[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_password = unpad(cipher.decrypt(cipher_text), AES.block_size)
    return decrypted_password.decode('utf-8')

# Función para guardar una contraseña en la base de datos
def save_password():
    application = app_entry.get()
    category = category_combo.get()
    username = username_entry.get()
    email = email_entry.get()
    password = encrypt_password(password_entry.get())

    cursor.execute("INSERT INTO passwords (application, category, username, email, password) VALUES (?, ?, ?, ?, ?)",
                   (application, category, username, email, password))
    conn.commit()

    messagebox.showinfo("Éxito", "Contraseña guardada correctamente.")

    clear_fields()


# Función para cargar las contraseñas desde la base de datos y mostrarlas en la tabla
def load_passwords():
    clear_table()
    cursor.execute("SELECT * FROM passwords")
    rows = cursor.fetchall()

    for row in rows:
        tree.insert("", tk.END, values=row)


def update_password():
    selected_item = tree.selection()
    if not selected_item:
        messagebox.showwarning("Advertencia", "Por favor, seleccione una contraseña para actualizar.")
        return

    confirmed = messagebox.askyesno("Confirmar", "¿Está seguro de que desea actualizar esta contraseña?")
    if confirmed:
        item_id = tree.item(selected_item)['values'][0]
        application = app_entry.get()
        category = category_combo.get()
        username = username_entry.get()
        email = email_entry.get()
        password = encrypt_password(password_entry.get())

        cursor.execute("UPDATE passwords SET application=?, category=?, username=?, email=?, password=? WHERE id=?",
                       (application, category, username, email, password, item_id))
        conn.commit()

        messagebox.showinfo("Éxito", "Contraseña actualizada correctamente.")

        clear_fields()
        clear_table()
        load_passwords()


# Función para borrar una contraseña de la base de datos
def delete_password():
    selected_item = tree.selection()
    if not selected_item:
        messagebox.showwarning("Advertencia", "Por favor, seleccione una contraseña para eliminar.")
        return

    confirmed = messagebox.askyesno("Confirmar", "¿Está seguro de que desea eliminar esta contraseña?")
    if confirmed:
        item_id = tree.item(selected_item)['values'][0]
        cursor.execute("DELETE FROM passwords WHERE id=?", (item_id,))
        conn.commit()

        messagebox.showinfo("Éxito", "Contraseña eliminada correctamente.")

        clear_table()


# Función para cargar los datos de una contraseña seleccionada en los campos superiores para su edición
def edit_password(event):
    selected_item = tree.selection()
    if not selected_item:
        return

    values = tree.item(selected_item)['values']
    app_entry.delete(0, tk.END)
    app_entry.insert(tk.END, values[1])
    category_combo.set(values[2])
    username_entry.delete(0, tk.END)
    username_entry.insert(tk.END, values[3])
    email_entry.delete(0, tk.END)
    email_entry.insert(tk.END, values[4])
    password_entry.delete(0, tk.END)
    password = decrypt_password(values[5])
    password_entry.insert(tk.END, str(password))  # Convertir a cadena

    # Habilitar el campo de contraseña
    password_entry.config(state='normal')

    password_visibility_button.config(image=show_password_icon)


# Función para mostrar u ocultar la contraseña en texto plano
def toggle_password_visibility():
    if password_entry['show'] == '*':
        password_entry.config(show='')
        password_visibility_button.config(image=hide_password_icon)
    else:
        password_entry.config(show='*')
        password_visibility_button.config(image=show_password_icon)


# Función para limpiar los campos superiores
def clear_fields():
    app_entry.delete(0, tk.END)
    category_combo.set("")
    username_entry.delete(0, tk.END)
    email_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)


# Función para limpiar la tabla inferior
def clear_table():
    tree.delete(*tree.get_children())

key = load_key()
if key is None:
    key = get_random_bytes(16)
    save_key(key)

# Configuración de la interfaz gráfica
root = tk.Tk()
root.title("Gestor de Contraseñas")
root.geometry("1080x550+0+0")
root.resizable(0,0)
root.configure(bg="#e1f1f8")

# Estilos personalizados
style = ttk.Style()
style.configure("Custom.TLabel", font=("Calibri", 12, "bold"))
style.configure("Custom.TEntry", font=("Calibri", 12), relief=tk.SOLID)

# Cargar iconos
show_password_icon = PhotoImage(file="img/show_password.png")
hide_password_icon = PhotoImage(file="img/hide_password.png")

# Frame superior
top_frame = ttk.LabelFrame(root, text="Gestionar Contraseñas")
top_frame.place(x=10, width=1060, height=380)

# Etiquetas y campos de entrada
app_label = ttk.Label(top_frame, text="Aplicación:", style="Custom.TLabel")
app_label.grid(row=0, column=0, padx=10, pady=10)
app_entry = ttk.Entry(top_frame, style="Custom.TEntry")
app_entry.grid(row=0, column=1, padx=10, pady=10)
app_entry.configure(font=font.Font(size=16))  # Aumentar el tamaño de la fuente

category_label = ttk.Label(top_frame, text="Categoría:", style="Custom.TLabel")
category_label.grid(row=0, column=3, padx=10, pady=10)
category_combo = ttk.Combobox(top_frame, values=["Redes Sociales", "Correo Electrónico", "Banca en Línea"],
                             style="Custom.TCombobox")
category_combo.grid(row=0, column=4, padx=10, pady=10)
category_combo.configure(font=font.Font(size=16))

username_label = ttk.Label(top_frame, text="Username:", style="Custom.TLabel")
username_label.grid(row=1, column=0, padx=10, pady=10)
username_entry = ttk.Entry(top_frame, style="Custom.TEntry")
username_entry.grid(row=1, column=1, padx=10, pady=10)
username_entry.configure(font=font.Font(size=16))  # Aumentar el tamaño de la fuente

email_label = ttk.Label(top_frame, text="Email:", style="Custom.TLabel")
email_label.grid(row=1, column=3, padx=10, pady=10)
email_entry = ttk.Entry(top_frame, style="Custom.TEntry")
email_entry.grid(row=1, column=4, padx=10, pady=10)
email_entry.configure(font=font.Font(size=16))  # Aumentar el tamaño de la fuente

password_label = ttk.Label(top_frame, text="Contraseña:", style="Custom.TLabel")
password_label.grid(row=2, column=0, padx=10, pady=10)
password_entry = ttk.Entry(top_frame, show="*", style="Custom.TEntry")
password_entry.grid(row=2, column=1, padx=10, pady=10)
password_entry.configure(font=font.Font(size=16))  # Aumentar el tamaño de la fuente

# Botones
save_button = tk.Button(top_frame, text="Añadir", command=save_password,font=("Calibri", 16, "bold"), width=15, bg="green", fg="white",)
save_button.grid(row=5, column=1, pady=15, padx=10)

update_button = tk.Button(top_frame, text="Actualizar", command=update_password,font=("Calibri", 16, "bold"), width=15, bg="blue", fg="white")
update_button.grid(row=5, column=2, pady=15, padx=10)

delete_button = tk.Button(top_frame, text="Eliminar", command=delete_password,font=("Calibri", 16, "bold"), width=15, bg="red", fg="white")
delete_button.grid(row=5, column=3, pady=15, padx=10)

load_button = tk.Button(top_frame, text="Mostrar Contraseñas", command=load_passwords,font=("Calibri", 16, "bold"), width=20, bg="black", fg="white")
load_button.grid(row=5, column=4, pady=15, padx=10)

clear_button = tk.Button(top_frame, text="Limpiar Campos", command=clear_fields,font=("Calibri", 16, "bold"), width=15, bg="orange", fg="white")
clear_button.grid(row=6, column=2, columnspan=2,padx=10)

# Frame inferior
bottom_frame = ttk.LabelFrame(root, text="Contraseñas Guardadas")
bottom_frame.place(x=10, y=320,width=1060, height=200)

# Tabla
tree = ttk.Treeview(bottom_frame, columns=("ID", "Aplicación", "Categoría", "Username", "Email", "Contraseña"),
                    selectmode="browse")
tree.heading("ID", text="ID")
tree.heading("Aplicación", text="Aplicación")
tree.heading("Categoría", text="Categoría")
tree.heading("Username", text="Username")
tree.heading("Email", text="Email")
tree.heading("Contraseña", text="Contraseña")
tree.column("#0", width=0, stretch=tk.NO)  # Columna vacía
tree.column("ID", width=30, anchor="center")
tree.column("Aplicación", width=100, anchor="center")
tree.column("Categoría", width=120, anchor="center")
tree.column("Username", width=100, anchor="center")
tree.column("Email", width=150, anchor="center")
tree.column("Contraseña", width=100, anchor="center")
tree.bind("<<TreeviewSelect>>", edit_password)
tree.pack(fill=tk.BOTH, expand=1)

# Scrollbar
scrollbar = ttk.Scrollbar(bottom_frame, orient="vertical", command=tree.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
tree.configure(yscrollcommand=scrollbar.set)

# Botón de visibilidad de contraseña
show_password_icon = show_password_icon.subsample(2)
hide_password_icon = hide_password_icon.subsample(2)
password_visibility_button = ttk.Button(top_frame, image=show_password_icon, command=toggle_password_visibility,
                                        style="Custom.TButton")
password_visibility_button.grid(row=2, column=2, padx=5, pady=5)

root.mainloop()

# Cerrar la conexión a la base de datos al finalizar
conn.close()
