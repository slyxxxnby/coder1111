import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import base64
import binascii
import re
from datetime import datetime
import hashlib
import zlib
import json
import os
from cryptography.fernet import Fernet
import pyperclip
import webbrowser


class AdvancedEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cipher Master Pro - Codificador/Decodificador Avanzado")
        self.root.geometry("1000x800")
        self.root.minsize(900, 700)
        
        # Configuración de icono (si está disponible)
        try:
            self.root.iconbitmap("cipher_icon.ico")
        except:
            pass

        # Configuración de colores
        self.colors = {
            "primary": "#1a237e",
            "secondary": "#ff6d00",
            "bg_light": "#f5f5f5",
            "text_dark": "#212121",
            "text_light": "#ffffff",
            "accent": "#00b0ff",
            "success": "#4caf50",
            "warning": "#ff9800",
            "error": "#f44336"
        }

        # Historial de conversiones
        self.history = []
        self.history_file = "history.json"
        self.load_history()

        # Clave de encriptación AES
        self.encryption_key = None
        self.key_file = "encryption.key"

        # Cargar o generar clave de encriptación
        self.load_or_generate_key()

        # Crear la interfaz
        self.create_widgets()

    def load_or_generate_key(self):
        """Carga o genera una clave de encriptación AES"""
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as key_file:
                self.encryption_key = key_file.read()
        else:
            self.encryption_key = Fernet.generate_key()
            with open(self.key_file, "wb") as key_file:
                key_file.write(self.encryption_key)

    def load_history(self):
        """Carga el historial desde archivo"""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, "r", encoding="utf-8") as f:
                    self.history = json.load(f)
            except:
                self.history = []

    def save_history(self):
        """Guarda el historial en archivo"""
        try:
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(self.history, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Error guardando historial: {e}")

    def add_to_history(self, operation, algorithm, input_text, output_text):
        """Añade una entrada al historial"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {
            "timestamp": timestamp,
            "operation": operation,
            "algorithm": algorithm,
            "input": input_text[:200] + "..." if len(input_text) > 200 else input_text,
            "output": output_text[:200] + "..." if len(output_text) > 200 else output_text,
            "full_input": input_text,
            "full_output": output_text
        }
        self.history.insert(0, entry)
        
        # Mantener solo los últimos 100 registros
        if len(self.history) > 100:
            self.history = self.history[:100]
        
        self.save_history()
        
        # Actualizar la vista de historial si existe
        if hasattr(self, "history_tree"):
            self.update_history_view()

    def create_widgets(self):
        """Crea todos los widgets de la interfaz"""
        # Configurar estilos
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TFrame", background=self.colors["bg_light"])
        style.configure("TButton", background=self.colors["secondary"], 
                        foreground=self.colors["text_light"],
                        font=("Segoe UI", 10, "bold"), padding=8)
        style.map("TButton", 
                 background=[("active", self.colors["accent"]), 
                            ("disabled", "#cccccc")])
        style.configure("TLabel", background=self.colors["bg_light"], 
                       foreground=self.colors["text_dark"],
                       font=("Segoe UI", 11))
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"),
                       foreground=self.colors["primary"])
        style.configure("History.Treeview", font=("Segoe UI", 10), rowheight=25)
        style.configure("History.Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=[10, 5])
        style.configure("TEntry", font=("Segoe UI", 11), padding=5)
        style.configure("TCombobox", font=("Segoe UI", 11), padding=5)

        # Frame principal con padding
        content_frame = ttk.Frame(self.root, padding=(15, 15, 15, 15))
        content_frame.pack(fill="both", expand=True)

        # Título
        title_frame = ttk.Frame(content_frame)
        title_frame.pack(fill="x", pady=(0, 10))

        title_label = ttk.Label(title_frame, text="CIPHER MASTER PRO", 
                               style="Header.TLabel")
        title_label.pack(side="left")

        # Botón de ayuda
        help_btn = ttk.Button(title_frame, text="Ayuda", command=self.show_help,
                             style="TButton", width=8)
        help_btn.pack(side="right", padx=5)

        # Botón de información
        info_btn = ttk.Button(title_frame, text="Info", command=self.show_info,
                             style="TButton", width=8)
        info_btn.pack(side="right", padx=5)

        subtitle_label = ttk.Label(content_frame,
                                  text="Sistema Avanzado de Codificación y Decodificación",
                                  font=("Segoe UI", 12))
        subtitle_label.pack()

        # Pestañas
        notebook = ttk.Notebook(content_frame)
        notebook.pack(fill="both", expand=True)

        # Crear pestañas
        basic_frame = ttk.Frame(notebook, padding=10)
        advanced_frame = ttk.Frame(notebook, padding=10)
        history_frame = ttk.Frame(notebook, padding=10)
        tools_frame = ttk.Frame(notebook, padding=10)

        notebook.add(basic_frame, text="Codificación Básica")
        notebook.add(advanced_frame, text="Codificación Avanzada")
        notebook.add(history_frame, text="Historial")
        notebook.add(tools_frame, text="Herramientas")

        # Configurar las pestañas
        self.setup_basic_tab(basic_frame)
        self.setup_advanced_tab(advanced_frame)
        self.setup_history_tab(history_frame)
        self.setup_tools_tab(tools_frame)

        # Barra de estado
        self.status_var = tk.StringVar(value="Sistema listo para procesar datos")
        status_bar = ttk.Label(content_frame, textvariable=self.status_var, 
                              relief="sunken", anchor="w", 
                              background=self.colors["bg_light"])
        status_bar.pack(fill="x", side="bottom", pady=(10, 0))

    def setup_basic_tab(self, parent):
        """Configura la pestaña de codificación básica"""
        # Frame principal
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill="both", expand=True)

        # Panel de entrada
        input_frame = ttk.LabelFrame(main_frame, text="Texto a procesar", padding=10)
        input_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.input_text = scrolledtext.ScrolledText(
            input_frame, wrap=tk.WORD, font=("Consolas", 11), 
            undo=True, maxundo=20)
        self.input_text.pack(fill="both", expand=True)

        # Panel de botones y opciones
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill="x", pady=10)

        # Frame para algoritmos
        algo_frame = ttk.LabelFrame(control_frame, text="Algoritmo", padding=5)
        algo_frame.pack(side="left", padx=5, fill="x", expand=True)

        self.algo_var = tk.StringVar(value="base64")
        algorithms = [
            ("Base64", "base64"),
            ("Hexadecimal", "hex"),
            ("Binario", "binary"),
            ("URL", "url"),
            ("ROT13", "rot13")
        ]

        for text, value in algorithms:
            rb = ttk.Radiobutton(algo_frame, text=text, value=value, 
                                 variable=self.algo_var)
            rb.pack(side="left", padx=5)

        # Frame para botones de acción
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(side="right")

        encode_btn = ttk.Button(btn_frame, text="Codificar", 
                               command=self.encode_basic)
        encode_btn.pack(side="left", padx=5)

        decode_btn = ttk.Button(btn_frame, text="Decodificar", 
                               command=self.decode_basic)
        decode_btn.pack(side="left", padx=5)

        clear_btn = ttk.Button(btn_frame, text="Limpiar", 
                              command=self.clear_text)
        clear_btn.pack(side="left", padx=5)

        # Panel de salida
        output_frame = ttk.LabelFrame(main_frame, text="Resultado", padding=10)
        output_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.output_text = scrolledtext.ScrolledText(
            output_frame, wrap=tk.WORD, font=("Consolas", 11),
            state="normal", undo=True, maxundo=20)
        self.output_text.pack(fill="both", expand=True)

        # Panel de acciones para el resultado
        output_btn_frame = ttk.Frame(output_frame)
        output_btn_frame.pack(fill="x", pady=(5, 0))

        copy_btn = ttk.Button(output_btn_frame, text="Copiar", 
                             command=self.copy_output)
        copy_btn.pack(side="left", padx=5)

        save_btn = ttk.Button(output_btn_frame, text="Guardar en archivo", 
                             command=self.save_output)
        save_btn.pack(side="left", padx=5)

    def setup_advanced_tab(self, parent):
        """Configura la pestaña de codificación avanzada"""
        # Frame principal
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill="both", expand=True)

        # Panel de entrada
        input_frame = ttk.LabelFrame(main_frame, text="Texto a procesar", padding=10)
        input_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.adv_input_text = scrolledtext.ScrolledText(
            input_frame, wrap=tk.WORD, font=("Consolas", 11), 
            undo=True, maxundo=20)
        self.adv_input_text.pack(fill="both", expand=True)

        # Panel de botones y opciones
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill="x", pady=10)

        # Frame para algoritmos avanzados
        algo_frame = ttk.LabelFrame(control_frame, text="Algoritmo Avanzado", padding=5)
        algo_frame.pack(side="left", padx=5, fill="x", expand=True)

        self.adv_algo_var = tk.StringVar(value="aes")
        adv_algorithms = [
            ("AES", "aes"),
            ("Hash MD5", "md5"),
            ("Hash SHA-1", "sha1"),
            ("Hash SHA-256", "sha256"),
            ("Compresión", "compress")
        ]

        algo_menu = ttk.Combobox(algo_frame, textvariable=self.adv_algo_var, 
                                values=[a[0] for a in adv_algorithms], 
                                state="readonly")
        algo_menu.pack(side="left", padx=5, fill="x", expand=True)

        # Frame para botones de acción
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(side="right")

        encode_btn = ttk.Button(btn_frame, text="Codificar", 
                               command=self.encode_advanced)
        encode_btn.pack(side="left", padx=5)

        decode_btn = ttk.Button(btn_frame, text="Decodificar", 
                               command=self.decode_advanced)
        decode_btn.pack(side="left", padx=5)

        clear_btn = ttk.Button(btn_frame, text="Limpiar", 
                              command=lambda: self.adv_input_text.delete(1.0, tk.END))
        clear_btn.pack(side="left", padx=5)

        # Panel de salida
        output_frame = ttk.LabelFrame(main_frame, text="Resultado", padding=10)
        output_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.adv_output_text = scrolledtext.ScrolledText(
            output_frame, wrap=tk.WORD, font=("Consolas", 11),
            state="normal", undo=True, maxundo=20)
        self.adv_output_text.pack(fill="both", expand=True)

        # Panel de acciones para el resultado
        output_btn_frame = ttk.Frame(output_frame)
        output_btn_frame.pack(fill="x", pady=(5, 0))

        copy_btn = ttk.Button(output_btn_frame, text="Copiar", 
                             command=lambda: self.copy_output(advanced=True))
        copy_btn.pack(side="left", padx=5)

        save_btn = ttk.Button(output_btn_frame, text="Guardar en archivo", 
                             command=lambda: self.save_output(advanced=True))
        save_btn.pack(side="left", padx=5)

    def setup_history_tab(self, parent):
        """Configura la pestaña de historial"""
        # Frame principal
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill="both", expand=True)

        # Panel de controles
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill="x", pady=(0, 10))

        refresh_btn = ttk.Button(control_frame, text="Actualizar", 
                                command=self.update_history_view)
        refresh_btn.pack(side="left", padx=5)

        clear_btn = ttk.Button(control_frame, text="Limpiar Historial", 
                              command=self.clear_history)
        clear_btn.pack(side="left", padx=5)

        search_frame = ttk.Frame(control_frame)
        search_frame.pack(side="right")

        ttk.Label(search_frame, text="Buscar:").pack(side="left", padx=5)
        self.history_search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.history_search_var, width=20)
        search_entry.pack(side="left", padx=5)
        search_entry.bind("<KeyRelease>", lambda e: self.update_history_view())

        # Treeview para el historial
        history_frame = ttk.Frame(main_frame)
        history_frame.pack(fill="both", expand=True)

        columns = ("timestamp", "operation", "algorithm", "input", "output")
        self.history_tree = ttk.Treeview(
            history_frame, columns=columns, show="headings", 
            style="History.Treeview", selectmode="browse")
        
        # Configurar columnas
        self.history_tree.heading("timestamp", text="Fecha/Hora")
        self.history_tree.heading("operation", text="Operación")
        self.history_tree.heading("algorithm", text="Algoritmo")
        self.history_tree.heading("input", text="Entrada")
        self.history_tree.heading("output", text="Salida")

        self.history_tree.column("timestamp", width=150, anchor="center")
        self.history_tree.column("operation", width=100, anchor="center")
        self.history_tree.column("algorithm", width=120, anchor="center")
        self.history_tree.column("input", width=200)
        self.history_tree.column("output", width=200)

        # Scrollbar
        scrollbar = ttk.Scrollbar(history_frame, orient="vertical", 
                                 command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.history_tree.pack(fill="both", expand=True)

        # Doble click para ver detalles
        self.history_tree.bind("<Double-1>", self.show_history_detail)

        # Actualizar vista
        self.update_history_view()

    def setup_tools_tab(self, parent):
        """Configura la pestaña de herramientas adicionales"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Sección de generación de contraseñas
        pass_frame = ttk.LabelFrame(main_frame, text="Generador de Contraseñas", padding=10)
        pass_frame.pack(fill="x", pady=5)

        self.pass_length_var = tk.IntVar(value=12)
        self.pass_upper_var = tk.BooleanVar(value=True)
        self.pass_lower_var = tk.BooleanVar(value=True)
        self.pass_digits_var = tk.BooleanVar(value=True)
        self.pass_special_var = tk.BooleanVar(value=True)
        self.generated_pass_var = tk.StringVar()

        # Controles de generación
        ttk.Label(pass_frame, text="Longitud:").grid(row=0, column=0, sticky="w", padx=5)
        ttk.Spinbox(pass_frame, from_=8, to=50, textvariable=self.pass_length_var, 
                   width=5).grid(row=0, column=1, sticky="w", padx=5)

        ttk.Checkbutton(pass_frame, text="Mayúsculas", variable=self.pass_upper_var
                      ).grid(row=1, column=0, sticky="w", padx=5)
        ttk.Checkbutton(pass_frame, text="Minúsculas", variable=self.pass_lower_var
                      ).grid(row=1, column=1, sticky="w", padx=5)
        ttk.Checkbutton(pass_frame, text="Dígitos", variable=self.pass_digits_var
                      ).grid(row=2, column=0, sticky="w", padx=5)
        ttk.Checkbutton(pass_frame, text="Caracteres especiales", variable=self.pass_special_var
                      ).grid(row=2, column=1, sticky="w", padx=5)

        ttk.Button(pass_frame, text="Generar", command=self.generate_password
                  ).grid(row=3, column=0, pady=5, sticky="w", padx=5)

        ttk.Entry(pass_frame, textvariable=self.generated_pass_var, font=("Consolas", 12),
                 state="readonly").grid(row=4, column=0, columnspan=2, sticky="we", pady=5)

        ttk.Button(pass_frame, text="Copiar", command=self.copy_password
                  ).grid(row=4, column=2, padx=5)

        # Sección de análisis de texto
        analyze_frame = ttk.LabelFrame(main_frame, text="Análisis de Texto", padding=10)
        analyze_frame.pack(fill="x", pady=5)

        self.analyze_text = scrolledtext.ScrolledText(analyze_frame, wrap=tk.WORD, 
                                                    height=5, font=("Consolas", 11))
        self.analyze_text.pack(fill="x", pady=5)

        ttk.Button(analyze_frame, text="Analizar", command=self.analyze_input
                 ).pack(side="left", pady=5)

        # Resultados del análisis
        self.analysis_result = ttk.Label(analyze_frame, text="", 
                                       font=("Segoe UI", 10), wraplength=500)
        self.analysis_result.pack(fill="x", pady=5)

    def encode_basic(self):
        """Codifica el texto usando el algoritmo básico seleccionado"""
        input_text = self.input_text.get(1.0, tk.END).strip()
        if not input_text:
            messagebox.showwarning("Advertencia", "Por favor, ingresa texto para codificar.")
            return

        algorithm = self.algo_var.get()
        try:
            if algorithm == "base64":
                output_text = base64.b64encode(input_text.encode()).decode()
            elif algorithm == "hex":
                output_text = binascii.hexlify(input_text.encode()).decode()
            elif algorithm == "binary":
                output_text = ' '.join(format(ord(c), '08b') for c in input_text)
            elif algorithm == "url":
                import urllib.parse
                output_text = urllib.parse.quote_plus(input_text)
            elif algorithm == "rot13":
                output_text = input_text.translate(
                    str.maketrans(
                        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
            else:
                output_text = "Algoritmo no soportado"

            self.output_text.config(state="normal")
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, output_text)
            self.output_text.config(state="normal")
            
            self.add_to_history("Codificar", algorithm, input_text, output_text)
            self.status_var.set(f"Texto codificado con {algorithm.upper()} con éxito.")
        except Exception as e:
            messagebox.showerror("Error", f"Error al codificar: {str(e)}")
            self.status_var.set("Error al codificar el texto.")

    def decode_basic(self):
        """Decodifica el texto usando el algoritmo básico seleccionado"""
        input_text = self.input_text.get(1.0, tk.END).strip()
        if not input_text:
            messagebox.showwarning("Advertencia", "Por favor, ingresa texto para decodificar.")
            return

        algorithm = self.algo_var.get()
        try:
            if algorithm == "base64":
                output_text = base64.b64decode(input_text.encode()).decode()
            elif algorithm == "hex":
                output_text = binascii.unhexlify(input_text.encode()).decode()
            elif algorithm == "binary":
                binary_values = input_text.split()
                output_text = ''.join(chr(int(b, 2)) for b in binary_values)
            elif algorithm == "url":
                import urllib.parse
                output_text = urllib.parse.unquote_plus(input_text)
            elif algorithm == "rot13":
                output_text = input_text.translate(
                    str.maketrans(
                        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
            else:
                output_text = "Algoritmo no soportado"

            self.output_text.config(state="normal")
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, output_text)
            self.output_text.config(state="normal")
            
            self.add_to_history("Decodificar", algorithm, input_text, output_text)
            self.status_var.set(f"Texto decodificado con {algorithm.upper()} con éxito.")
        except Exception as e:
            messagebox.showerror("Error", f"Error al decodificar: {str(e)}")
            self.status_var.set("Error al decodificar el texto.")

    def encode_advanced(self):
        """Codifica el texto usando algoritmos avanzados"""
        input_text = self.adv_input_text.get(1.0, tk.END).strip()
        if not input_text:
            messagebox.showwarning("Advertencia", "Por favor, ingresa texto para codificar.")
            return

        algorithm = self.adv_algo_var.get()
        try:
            if algorithm == "aes":
                cipher = Fernet(self.encryption_key)
                output_text = cipher.encrypt(input_text.encode()).decode()
            elif algorithm == "md5":
                output_text = hashlib.md5(input_text.encode()).hexdigest()
            elif algorithm == "sha1":
                output_text = hashlib.sha1(input_text.encode()).hexdigest()
            elif algorithm == "sha256":
                output_text = hashlib.sha256(input_text.encode()).hexdigest()
            elif algorithm == "compress":
                output_text = base64.b64encode(zlib.compress(input_text.encode())).decode()
            else:
                output_text = "Algoritmo no soportado"

            self.adv_output_text.config(state="normal")
            self.adv_output_text.delete(1.0, tk.END)
            self.adv_output_text.insert(tk.END, output_text)
            self.adv_output_text.config(state="normal")
            
            self.add_to_history("Codificar (Adv)", algorithm, input_text, output_text)
            self.status_var.set(f"Texto codificado con {algorithm.upper()} con éxito.")
        except Exception as e:
            messagebox.showerror("Error", f"Error al codificar: {str(e)}")
            self.status_var.set("Error al codificar el texto.")

    def decode_advanced(self):
        """Decodifica el texto usando algoritmos avanzados"""
        input_text = self.adv_input_text.get(1.0, tk.END).strip()
        if not input_text:
            messagebox.showwarning("Advertencia", "Por favor, ingresa texto para decodificar.")
            return

        algorithm = self.adv_algo_var.get()
        try:
            if algorithm == "aes":
                cipher = Fernet(self.encryption_key)
                output_text = cipher.decrypt(input_text.encode()).decode()
            elif algorithm == "compress":
                output_text = zlib.decompress(base64.b64decode(input_text.encode())).decode()
            else:
                output_text = "Este algoritmo no soporta decodificación"

            self.adv_output_text.config(state="normal")
            self.adv_output_text.delete(1.0, tk.END)
            self.adv_output_text.insert(tk.END, output_text)
            self.adv_output_text.config(state="normal")
            
            if algorithm in ["aes", "compress"]:
                self.add_to_history("Decodificar (Adv)", algorithm, input_text, output_text)
                self.status_var.set(f"Texto decodificado con {algorithm.upper()} con éxito.")
            else:
                self.status_var.set("Este algoritmo no soporta decodificación")
        except Exception as e:
            messagebox.showerror("Error", f"Error al decodificar: {str(e)}")
            self.status_var.set("Error al decodificar el texto.")

    def clear_text(self):
        """Limpia los campos de entrada y salida"""
        self.input_text.delete(1.0, tk.END)
        self.output_text.config(state="normal")
        self.output_text.delete(1.0, tk.END)
        self.status_var.set("Campos limpiados.")

    def copy_output(self, advanced=False):
        """Copia el texto de salida al portapapeles"""
        if advanced:
            text = self.adv_output_text.get(1.0, tk.END).strip()
        else:
            text = self.output_text.get(1.0, tk.END).strip()
        
        if text:
            pyperclip.copy(text)
            self.status_var.set("Texto copiado al portapapeles.")
        else:
            messagebox.showwarning("Advertencia", "No hay texto para copiar.")

    def save_output(self, advanced=False):
        """Guarda el texto de salida en un archivo"""
        if advanced:
            text = self.adv_output_text.get(1.0, tk.END).strip()
        else:
            text = self.output_text.get(1.0, tk.END).strip()
        
        if not text:
            messagebox.showwarning("Advertencia", "No hay texto para guardar.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")],
            title="Guardar archivo")
        
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(text)
                self.status_var.set(f"Archivo guardado en: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo guardar el archivo: {str(e)}")

    def update_history_view(self):
        """Actualiza la vista del historial con los datos actuales"""
        search_term = self.history_search_var.get().lower()
        
        self.history_tree.delete(*self.history_tree.get_children())
        
        for entry in self.history:
            if (not search_term or 
                search_term in entry["timestamp"].lower() or 
                search_term in entry["operation"].lower() or 
                search_term in entry["algorithm"].lower() or 
                search_term in entry["input"].lower() or 
                search_term in entry["output"].lower()):
                
                self.history_tree.insert("", "end", values=(
                    entry["timestamp"],
                    entry["operation"],
                    entry["algorithm"],
                    entry["input"],
                    entry["output"]
                ))

    def clear_history(self):
        """Limpia el historial"""
        if messagebox.askyesno("Confirmar", "¿Estás seguro de que deseas borrar todo el historial?"):
            self.history = []
            self.save_history()
            self.update_history_view()
            self.status_var.set("Historial borrado.")

    def show_history_detail(self, event):
        """Muestra el detalle completo de una entrada del historial"""
        item = self.history_tree.selection()
        if not item:
            return
            
        item_index = self.history_tree.index(item[0])
        if 0 <= item_index < len(self.history):
            entry = self.history[item_index]
            
            detail_window = tk.Toplevel(self.root)
            detail_window.title("Detalle del Historial")
            detail_window.geometry("700x500")
            
            main_frame = ttk.Frame(detail_window, padding=10)
            main_frame.pack(fill="both", expand=True)
            
            # Información general
            info_frame = ttk.LabelFrame(main_frame, text="Información", padding=10)
            info_frame.pack(fill="x", pady=5)
            
            ttk.Label(info_frame, text=f"Fecha/Hora: {entry['timestamp']}").pack(anchor="w")
            ttk.Label(info_frame, text=f"Operación: {entry['operation']}").pack(anchor="w")
            ttk.Label(info_frame, text=f"Algoritmo: {entry['algorithm']}").pack(anchor="w")
            
            # Entrada
            input_frame = ttk.LabelFrame(main_frame, text="Entrada Completa", padding=10)
            input_frame.pack(fill="both", expand=True, pady=5)
            
            input_text = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, 
                                                 font=("Consolas", 11))
            input_text.insert(tk.END, entry["full_input"])
            input_text.config(state="disabled")
            input_text.pack(fill="both", expand=True)
            
            # Salida
            output_frame = ttk.LabelFrame(main_frame, text="Salida Completa", padding=10)
            output_frame.pack(fill="both", expand=True, pady=5)
            
            output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, 
                                                  font=("Consolas", 11))
            output_text.insert(tk.END, entry["full_output"])
            output_text.config(state="disabled")
            output_text.pack(fill="both", expand=True)
            
            # Botón para cerrar
            btn_frame = ttk.Frame(main_frame)
            btn_frame.pack(fill="x", pady=5)
            
            ttk.Button(btn_frame, text="Cerrar", command=detail_window.destroy
                      ).pack(side="right")

    def generate_password(self):
        """Genera una contraseña segura"""
        import random
        import string
        
        length = self.pass_length_var.get()
        use_upper = self.pass_upper_var.get()
        use_lower = self.pass_lower_var.get()
        use_digits = self.pass_digits_var.get()
        use_special = self.pass_special_var.get()
        
        if not any([use_upper, use_lower, use_digits, use_special]):
            messagebox.showwarning("Advertencia", "Selecciona al menos un tipo de caracter.")
            return
        
        chars = ""
        if use_upper:
            chars += string.ascii_uppercase
        if use_lower:
            chars += string.ascii_lowercase
        if use_digits:
            chars += string.digits
        if use_special:
            chars += "!@#$%^&*()_-+=[]{}|;:,.<>?"
        
        password = ''.join(random.choice(chars) for _ in range(length))
        self.generated_pass_var.set(password)
        
        # Calcular fortaleza de la contraseña
        strength = "Fuerte"
        if length < 10:
            strength = "Moderada"
        if length < 8:
            strength = "Débil"
        
        self.status_var.set(f"Contraseña generada ({strength})")

    def copy_password(self):
        """Copia la contraseña generada al portapapeles"""
        password = self.generated_pass_var.get()
        if password:
            pyperclip.copy(password)
            self.status_var.set("Contraseña copiada al portapapeles.")
        else:
            messagebox.showwarning("Advertencia", "No hay contraseña para copiar.")

    def analyze_input(self):
        """Analiza el texto de entrada"""
        text = self.analyze_text.get(1.0, tk.END)
        
        if not text.strip():
            messagebox.showwarning("Advertencia", "Ingresa texto para analizar.")
            return
        
        # Estadísticas básicas
        char_count = len(text)
        word_count = len(re.findall(r'\w+', text))
        line_count = len(text.splitlines())
        
        # Detección de patrones
        emails = re.findall(r'\b[\w.-]+@[\w.-]+\.\w+\b', text)
        urls = re.findall(r'https?://[^\s]+', text)
        ip_addresses = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
        
        result = (
            f"Caracteres: {char_count} | Palabras: {word_count} | Líneas: {line_count}\n"
            f"Emails encontrados: {len(emails)}\n"
            f"URLs encontradas: {len(urls)}\n"
            f"Direcciones IP encontradas: {len(ip_addresses)}"
        )
        
        self.analysis_result.config(text=result)
        self.status_var.set("Análisis completado.")

    def show_info(self):
        """Muestra información sobre la aplicación"""
        info_text = (
            "Cipher Master Pro v2.0\n\n"
            "Sistema avanzado de codificación y decodificación\n"
            "Desarrollado por Expertos en Seguridad\n\n"
            "© 2023 Todos los derechos reservados"
        )
        messagebox.showinfo("Información", info_text)

    def show_help(self):
        """Muestra la ayuda de la aplicación"""
        help_text = (
            "Guía de uso de Cipher Master Pro:\n\n"
            "1. Codificación Básica:\n"
            "   - Selecciona un algoritmo (Base64, Hex, etc.)\n"
            "   - Ingresa el texto a codificar/decodificar\n"
            "   - Haz clic en el botón correspondiente\n\n"
            "2. Codificación Avanzada:\n"
            "   - Algoritmos más complejos como AES y hashes\n"
            "   - Algunos algoritmos no tienen decodificación\n\n"
            "3. Historial:\n"
            "   - Registro de todas las operaciones realizadas\n"
            "   - Doble clic para ver detalles completos\n\n"
            "4. Herramientas:\n"
            "   - Generador de contraseñas seguras\n"
            "   - Analizador de texto para detectar patrones"
        )
        
        help_window = tk.Toplevel(self.root)
        help_window.title("Ayuda de Cipher Master Pro")
        help_window.geometry("600x400")
        
        text = scrolledtext.ScrolledText(help_window, wrap=tk.WORD, padx=10, pady=10)
        text.insert(tk.END, help_text)
        text.config(state="disabled")
        text.pack(fill="both", expand=True)
        
        btn_frame = ttk.Frame(help_window)
        btn_frame.pack(fill="x", pady=5)
        
        ttk.Button(btn_frame, text="Documentación Online", 
                  command=lambda: webbrowser.open("https://ejemplo.com/docs")
                 ).pack(side="left", padx=10)
        
        ttk.Button(btn_frame, text="Cerrar", command=help_window.destroy
                  ).pack(side="right", padx=10)


if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedEncryptorApp(root)
    root.mainloop()
