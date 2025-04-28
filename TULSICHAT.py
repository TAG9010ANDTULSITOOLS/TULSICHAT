# --- Tulsi Encrypted Messenger App ---

import os
import json
import socket
import threading
import random
import hashlib
import traceback

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.clock import Clock

# --- Constants ---
PORT = 5000
BUFFER_SIZE = 4096
TIME_TO_DELETE = 300  # 5 minutes

# --- Encryption Functions ---

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    return private_key, private_key.public_key()

def encrypt_rsa(public_key, data):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_rsa(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def encrypt_aes(session_key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext) + encryptor.finalize()

def decrypt_aes(session_key, ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext[16:]) + decryptor.finalize()

# --- Main App ---

class MessengerLayout(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', **kwargs)

        self.device_id = self.load_or_generate_device_id()
        self.private_key, self.public_key = generate_rsa_keys()
        self.partner_public_key = None
        self.session_key = None
        self.connection = None
        self.is_secure = False

        self.alias_input = TextInput(hint_text='Alias', size_hint_y=None, height=40)
        self.add_widget(self.alias_input)

        self.hashcode_label = Label(text=f'Device ID: {self.device_id}', size_hint_y=None, height=30)
        self.add_widget(self.hashcode_label)

        self.session_label = Label(text='Session: ❌ Insecure', size_hint_y=None, height=30, color=(1,0,0,1))
        self.add_widget(self.session_label)

        self.partner_input = TextInput(hint_text='Partner Alias#Code', size_hint_y=None, height=40)
        self.add_widget(self.partner_input)

        self.chat_area = TextInput(readonly=True, size_hint_y=0.7)
        self.add_widget(self.chat_area)

        self.message_input = TextInput(hint_text='Enter your message', size_hint_y=None, height=40)
        self.add_widget(self.message_input)

        button_bar = BoxLayout(size_hint_y=None, height=40)
        send_btn = Button(text='Send')
        send_btn.bind(on_press=self.send_message)
        button_bar.add_widget(send_btn)

        file_btn = Button(text='Send File')
        file_btn.bind(on_press=self.send_file)
        button_bar.add_widget(file_btn)

        view_code_btn = Button(text='View Code')
        view_code_btn.bind(on_press=self.view_code)
        button_bar.add_widget(view_code_btn)

        blind_mode_btn = Button(text='Tulsi Blind Mode')
        blind_mode_btn.bind(on_press=self.enter_blind_mode)
        button_bar.add_widget(blind_mode_btn)

        self.add_widget(button_bar)

        threading.Thread(target=self.start_server, daemon=True).start()

    def load_or_generate_device_id(self):
        try:
            if os.path.exists('device_id.json'):
                with open('device_id.json', 'r') as f:
                    return json.load(f)['id']
            else:
                device_id = hashlib.sha256(str(random.random()).encode()).hexdigest()[:10]
                with open('device_id.json', 'w') as f:
                    json.dump({'id': device_id}, f)
                return device_id
        except:
            return "unknown"

    def update_session_label(self):
        if self.is_secure:
            self.session_label.text = 'Session: ✅ Secure'
            self.session_label.color = (0,1,0,1)
        else:
            self.session_label.text = 'Session: ❌ Insecure'
            self.session_label.color = (1,0,0,1)

    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', PORT))
        server.listen(5)
        while True:
            conn, _ = server.accept()
            threading.Thread(target=self.handle_connection, args=(conn,), daemon=True).start()

    def handle_connection(self, conn):
        try:
            peer_pubkey = serialization.load_pem_public_key(conn.recv(BUFFER_SIZE))
            conn.sendall(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            session_key_encrypted = conn.recv(BUFFER_SIZE)
            self.session_key = decrypt_rsa(self.private_key, session_key_encrypted)
            self.is_secure = True
            Clock.schedule_once(lambda dt: self.update_session_label())
            self.connection = conn

            while True:
                data = conn.recv(BUFFER_SIZE)
                if not data:
                    break
                plaintext = decrypt_aes(self.session_key, data)
                self.display_message(plaintext.decode())
                Clock.schedule_once(lambda dt: self.delete_message(plaintext.decode()), TIME_TO_DELETE)
        except:
            traceback.print_exc()
            self.is_secure = False
            Clock.schedule_once(lambda dt: self.update_session_label())
        finally:
            conn.close()

    def connect_to_partner(self, ip_address='127.0.0.1'):
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.connect((ip_address, PORT))
            conn.sendall(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            self.partner_public_key = serialization.load_pem_public_key(conn.recv(BUFFER_SIZE))
            session_key = os.urandom(32)
            conn.sendall(encrypt_rsa(self.partner_public_key, session_key))
            self.session_key = session_key
            self.is_secure = True
            Clock.schedule_once(lambda dt: self.update_session_label())
            self.connection = conn
            return conn
        except:
            traceback.print_exc()
            self.is_secure = False
            Clock.schedule_once(lambda dt: self.update_session_label())
            return None

    def send_message(self, instance):
        if not self.connection:
            self.connection = self.connect_to_partner()
            if not self.connection:
                return
        msg = f"{self.alias_input.text} ({self.device_id}): {self.message_input.text.strip()}"
        encrypted = encrypt_aes(self.session_key, msg.encode())
        self.connection.sendall(encrypted)
        self.display_message(msg)
        self.message_input.text = ''

    def send_file(self, instance):
        try:
            filepath = self.message_input.text.strip()
            if os.path.exists(filepath):
                with open(filepath, 'rb') as f:
                    file_data = f.read()
                filename = os.path.basename(filepath)
                payload = f"FILE:{filename}:".encode() + file_data
                encrypted = encrypt_aes(self.session_key, payload)
                self.connection.sendall(encrypted)
                self.display_message(f"[Sent file: {filename}]")
        except:
            traceback.print_exc()

    def display_message(self, msg):
        self.chat_area.text += msg + "\n"

    def delete_message(self, msg):
        self.chat_area.text = self.chat_area.text.replace(msg + "\n", "")

    def view_code(self, instance):
        try:
            with open(__file__, 'r') as f:
                code = f.read()
            popup = Popup(title='View Code', content=TextInput(text=code, readonly=True), size_hint=(0.9,0.9))
            popup.open()
        except:
            traceback.print_exc()

    def enter_blind_mode(self, instance):
        try:
            with open(__file__, 'r') as f:
                code = f.read()

            self.original_blind_code = code
            self.blind_editor = TextInput(text=code, multiline=True)
            self.blind_editor.bind(text=self.check_syntax_errors)

            undo_btn = Button(text='Undo')
            undo_btn.bind(on_press=self.reset_blind_code)

            container = BoxLayout(orientation='vertical')
            container.add_widget(self.blind_editor)
            container.add_widget(undo_btn)

            popup = Popup(title='Tulsi Blind Mode', content=container, size_hint=(0.95,0.95))
            popup.open()

        except:
            traceback.print_exc()

    def check_syntax_errors(self, instance, value):
        text = self.blind_editor.text
        if (text.count('"') % 2 != 0 or text.count("'") % 2 != 0 or
            text.count('(') != text.count(')') or text.count('{') != text.count('}')):
            self.blind_editor.foreground_color = (1, 0, 0, 1)
        else:
            self.blind_editor.foreground_color = (1, 1, 1, 1)

    def reset_blind_code(self, instance):
        self.blind_editor.text = self.original_blind_code

class TulsiMessengerApp(App):
    def build(self):
        return MessengerLayout()

if __name__ == '__main__':
    TulsiMessengerApp().run()
