import os
import sys
import os.path
import hashlib
import webbrowser
from random import randint
from kivy.metrics import dp
from kivy.clock import Clock
from kivymd.app import MDApp
from kivy.utils import platform
from kivy.uix.image import Image
from PIL import Image, ImageDraw
from json import dumps, loads, load
from kivy.core.window import Window
from check_password import check_password
from plyer import filechooser, storagepath
from kivy.uix.floatlayout import FloatLayout
from kivy.network.urlrequest import UrlRequest
from kivy.uix.anchorlayout import AnchorLayout
from kivymd.uix.filemanager import MDFileManager
from kivymd.uix.list import TwoLineAvatarIconListItem
from cryptography.hazmat.backends import default_backend
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.properties import StringProperty, ListProperty
from cryptography.hazmat.primitives.asymmetric import rsa
from kivymd.uix.list import ImageRightWidget, IconLeftWidget
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding

if platform == 'android':
    from permissions.location import check_permission, ask_permission

    is_android = True
else:
    is_android = False

Window.keyboard_anim_args = {'d': .2, 't': 'in_out_expo'}
Window.softinput_mode = "below_target"

URL = 'https://IP:PORT'
headers = {'Content-type': 'application/json',
           'Accept': 'text/plain'}
fil_avail_profile_ext_plyer = [["Picture", "*.jpg", "*.png"]]
picture_path = storagepath.get_pictures_dir()
app_path = storagepath.get_application_dir()
if is_android:
    shared_dir = os.path.join(storagepath.get_external_storage_dir(), 'RocketSender')
else:
    shared_dir = 'RocketSender'

vievedMyColor = (.8, .89, 1, .05)
unviewedMyColor = (.7, .79, 1, .05)
vievedOtherColor = (236 / 255, 237 / 255, 241 / 255, .05)


def check_path():
    if not os.path.exists(shared_dir):
        os.mkdir(shared_dir)

    if not os.path.exists(os.path.join(shared_dir, 'keys')):
        os.mkdir(os.path.join(shared_dir, 'keys'))

    if not os.path.exists(os.path.join(shared_dir, 'avatars')):
        os.mkdir(os.path.join(shared_dir, 'avatars'))

    if not os.path.exists(os.path.join(shared_dir, 'names')):
        os.mkdir(os.path.join(shared_dir, 'names'))

    if not os.path.exists(os.path.join(shared_dir, 'login')):
        os.mkdir(os.path.join(shared_dir, 'login'))

    if not os.path.exists(os.path.join(shared_dir, 'temp')):
        os.mkdir(os.path.join(shared_dir, 'temp'))


is_first_start = True
try:
    with open(os.path.join(shared_dir, 'login', 'credentials.json'), 'r', encoding='utf-8') as f:
        is_first_start = False
except Exception:
    is_first_start = True


def check_storage_permission():
    if is_android:
        ok = check_permission("android.permission.WRITE_EXTERNAL_STORAGE")
    else:
        ok = True
    return ok


def request_storage_permission():
    if is_android:
        ask_permission("android.permission.WRITE_EXTERNAL_STORAGE")


def prepare_mask(size, antialias=2):
    mask = Image.new('L', (size[0] * antialias, size[1] * antialias), 0)
    ImageDraw.Draw(mask).ellipse((0, 0) + mask.size, fill=255)
    return mask.resize(size, Image.ANTIALIAS)


def crop(im, s):
    w, h = im.size
    k = w / s[0] - h / s[1]
    if k > 0:
        im = im.crop(((w - h) / 2, 0, (w + h) / 2, h))
    elif k < 0:
        im = im.crop((0, (h - w) / 2, w, (h + w) / 2))
    return im.resize(s, Image.ANTIALIAS)


def make_avatar(name_in, name_out):
    size = (512, 512)
    im = Image.open(name_in)
    im = crop(im, size)
    im.putalpha(prepare_mask(size, 4))
    im.save(name_out, 'PNG', quality=20, optimize=True)
    return name_out


def check_key(key):
    credentials = load(open(os.path.join(shared_dir, 'temp', 'temp_login'), encoding='utf-8'))
    try:
        key = int(key)
        key = bytes.fromhex(hex(key).replace('0x', ''))
        key_s = key.decode('utf-8')
        data = 'test'.encode('utf-8')

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        backend = default_backend()
        key = os.urandom(32)
        iv = os.urandom(16)
        key_iv = key + iv
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        users_pub = serialization.load_pem_public_key(bytes(credentials["public_key"], "utf-8"),
                                                      backend=default_backend())
        my_private = serialization.load_pem_private_key(key_s.encode('utf-8'),
                                                        password=bytes(credentials["password"], "utf-8"),
                                                        backend=default_backend())
        my_pub = my_private.public_key()
        user_encrypted_key = users_pub.encrypt(
            key_iv,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )
        my_encrypted_key = my_pub.encrypt(
            key_iv,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )
        signature = my_private.sign(
            hashlib.sha512(data).digest(),
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA512()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )

        payload_out = {
            "status": "OK",
            "data": encrypted_data.hex(),
            "signature": signature.hex(),
        }
        user_key = my_encrypted_key.hex()
        unpadder = padding.PKCS7(128).unpadder()
        my_private = serialization.load_pem_private_key(key_s.encode('utf-8'),
                                                        password=bytes(credentials["password"], "utf-8"),
                                                        backend=default_backend())

        public_key = serialization.load_pem_public_key(bytes(credentials["public_key"], "utf-8"),
                                                       backend=default_backend())

        key_iv = my_private.decrypt(
            bytes.fromhex(user_key),
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )

        key = key_iv[:32]
        iv = key_iv[32:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(bytes.fromhex(payload_out["data"])) + decryptor.finalize()
        decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

        public_key.verify(
            bytes.fromhex(payload_out["signature"]),
            hashlib.sha512(decrypted_data).digest(),
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA512()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        data_ok = decrypted_data.decode("utf-8")
        if data_ok != 'test':
            return False
        return True
    except Exception as e:
        return False


def get_public_key(username):
    credentials = load(open(os.path.join(shared_dir, 'login', 'credentials.json'), encoding='utf-8'))
    data = {'login': credentials['login'], 'password': credentials['password'], 'username': username}
    data = dumps(data)
    public_request = UrlRequest(url=URL + '/api/get_public_key', req_body=data, method='GET', req_headers=headers,
                                verify=False)
    public_request.wait()
    result = public_request.result
    if result is None:
        return

    if result['status'] == 'OK':
        public_key = result['public_key']
        with open(os.path.join(shared_dir, 'keys', username.replace('@', '')), 'w', encoding='utf-8') as f:
            f.write(public_key)


def decrypt_message(message):
    try:
        credentials = load(open(os.path.join(shared_dir, 'login', "credentials.json")))
        unpadder = padding.PKCS7(128).unpadder()
        my_private = serialization.load_pem_private_key(
            open(
                os.path.join(shared_dir, 'login',
                             hashlib.sha512(bytes(credentials["login"], "utf-8")).hexdigest() + ".pem"),
                "rb").read(),
            password=bytes(credentials["password"], "utf-8"), backend=default_backend())
        if message["sent_by"] == credentials["username"]:
            public_key = my_private.public_key()
        else:
            if os.path.exists(os.path.join(shared_dir, 'keys', message['sent_by'].replace('@', ''))):
                with open(os.path.join(shared_dir, 'keys', message['sent_by'].replace('@', '')), 'r',
                          encoding='utf-8') as f:
                    public_key = f.read()
                public_key = serialization.load_pem_public_key(bytes(public_key, "utf-8"), backend=default_backend())
            else:
                get_public_key(message['sent_by'])
                if os.path.exists(os.path.join(shared_dir, 'keys', message['sent_by'].replace('@', ''))):
                    with open(os.path.join(shared_dir, 'keys', message['sent_by'].replace('@', '')), 'r',
                              encoding='utf-8') as f:
                        public_key = f.read()
                    public_key = serialization.load_pem_public_key(bytes(public_key, "utf-8"),
                                                                   backend=default_backend())
                else:
                    return {"status": "error", "error": "Error getting users public key"}
        key_iv = my_private.decrypt(
            bytes.fromhex(message["key"]),
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )
        key = key_iv[:32]
        iv = key_iv[32:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(bytes.fromhex(message["data"])) + decryptor.finalize()
        decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()
        public_key.verify(
            bytes.fromhex(message["signature"]),
            hashlib.sha512(decrypted_data).digest(),
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA512()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        return {"status": "OK", "data": decrypted_data.decode("utf-8"),
                "sent_by": message["sent_by"], "type": int(message["type"]),
                "unix_time": message["unix_time"], "viewed": message["viewed"]}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def encrypt_message(type_, data, chat_id, username):
    credentials = load(open(os.path.join(shared_dir, 'login', "credentials.json")))
    if os.path.exists(os.path.join(shared_dir, 'keys', username.replace('@', ''))):
        with open(os.path.join(shared_dir, 'keys', username.replace('@', '')), 'r',
                  encoding='utf-8') as f:
            public_key = f.read()
    else:
        get_public_key(username)
        if os.path.exists(os.path.join(shared_dir, 'keys', username.replace('@', ''))):
            with open(os.path.join(shared_dir, 'keys', username.replace('@', '')), 'r',
                      encoding='utf-8') as f:
                public_key = f.read()
        else:
            return {"status": "error", "error": "Error getting users public key"}
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    backend = default_backend()
    key = os.urandom(32)
    iv = os.urandom(16)
    key_iv = key + iv
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    users_pub = serialization.load_pem_public_key(bytes(public_key, "utf-8"), backend=default_backend())
    my_private = serialization.load_pem_private_key(
        open(os.path.join(shared_dir, 'login',
                          hashlib.sha512(bytes(credentials["login"], "utf-8")).hexdigest() + ".pem"),
             "rb").read(),
        password=bytes(credentials["password"], "utf-8"), backend=default_backend())
    my_pub = my_private.public_key()
    user_encrypted_key = users_pub.encrypt(
        key_iv,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )
    my_encrypted_key = my_pub.encrypt(
        key_iv,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )
    signature = my_private.sign(
        hashlib.sha512(data).digest(),
        asymmetric_padding.PSS(
            mgf=asymmetric_padding.MGF1(hashes.SHA512()),
            salt_length=asymmetric_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA512()
    )
    users_keys = {username: user_encrypted_key.hex(), credentials["username"]: my_encrypted_key.hex()}
    if type_ == 1:
        payload = {
            "login": credentials['login'],
            "password": credentials['password'],
            "type": type_,
            "data": encrypted_data.hex(),
            "signature": signature.hex(),
            "chat_id": chat_id,
            "keys": users_keys
        }
        return payload


class OtherMessageLabel(AnchorLayout):
    text = StringProperty()
    color_out = ListProperty()


class MyMessageLabel(AnchorLayout):
    text = StringProperty()
    color_out = ListProperty()


class Manager(ScreenManager):
    def __init__(self, **kwargs):
        self.login = ''
        self.password = ''
        self.email = ''
        self.current_chat = None
        self.current_photo = None
        super(Manager, self).__init__(**kwargs)
        if is_first_start:
            self.add_widget(StartScreen())
            self.add_widget(RegisterScreen())
            self.add_widget(InfoRegisterScreen())
            self.add_widget(ConfirmEmailScreen())
            self.add_widget(ChatsScreen())
            self.add_widget(AddChatScreen())
            self.add_widget(MessageScreen())
            self.add_widget(ReadPrivateKey())
            self.add_widget(RebootScreen())
            self.add_widget(SettingsScreen())
            self.add_widget(EditChatScreen())
            self.add_widget(AboutScreen())
        else:
            self.add_widget(ChatsScreen())
            self.add_widget(StartScreen())
            self.add_widget(RegisterScreen())
            self.add_widget(InfoRegisterScreen())
            self.add_widget(ConfirmEmailScreen())
            self.add_widget(AddChatScreen())
            self.add_widget(MessageScreen())
            self.add_widget(RebootScreen())
            self.add_widget(SettingsScreen())
            self.add_widget(EditChatScreen())
            self.add_widget(AboutScreen())


class Logo(FloatLayout):
    pass


class InfoRegisterScreen(Screen):
    def __init__(self, **kwargs):
        super(InfoRegisterScreen, self).__init__(**kwargs)
        Window.bind(on_keyboard=self.events_program)

    def on_pre_enter(self, *args):
        Window.bind(on_keyboard=self.events_program)

    def events_program(self, instance, keyboard, keycode, text, modifiers):
        if keyboard in (1001, 27):
            pass
        return True


class AboutScreen(Screen, Logo):
    def __init__(self, **kwargs):
        super(AboutScreen, self).__init__(**kwargs)
        Window.bind(on_keyboard=self.events_program)

    def events_program(self, instance, keyboard, keycode, text, modifiers):
        if keyboard in (1001, 27):
            self.go_to_settings()
        return True

    def go_to_settings(self, *args):
        self.manager.current = 'settings_screen'

    def on_open_refs(self, ref):
        webbrowser.open(ref)

    def on_pre_enter(self, *args):
        Window.bind(on_keyboard=self.events_program)


class SettingsScreen(Screen):
    def __init__(self, **kwargs):
        super(SettingsScreen, self).__init__(**kwargs)
        Window.bind(on_keyboard=self.events_program)

    def events_program(self, instance, keyboard, keycode, text, modifiers):
        if keyboard in (1001, 27):
            self.go_to_chats()
        return True

    def on_pre_enter(self, *args):
        Window.bind(on_keyboard=self.events_program)
        self.credentials = load(open(os.path.join(shared_dir, 'login', "credentials.json")))
        self.ids.username.secondary_text = self.credentials['username']

    def go_to_chats(self, *args):
        self.manager.current = 'chats'

    def on_help_project(self, *args):
        webbrowser.open('https://google.com')

    def go_to_about(self, *args):
        self.manager.current = 'about'

    def on_logout(self, *args):
        credentials = load(open(os.path.join(shared_dir, 'login', "credentials.json")))
        username = credentials['username']
        os.remove(os.path.join(shared_dir, 'login',
                               hashlib.sha512(bytes(credentials["login"], "utf-8")).hexdigest() + ".pem"))
        os.remove(os.path.join(shared_dir, 'login', "credentials.json"))
        sys.exit()


class RegisterScreen(Screen, Logo):
    def __init__(self, **kwargs):
        super(RegisterScreen, self).__init__(**kwargs)
        self.login = ''
        self.email = ''
        self.password = ''
        self.password_2 = ''
        self.register_request = None
        Window.bind(on_keyboard=self.events_program)

    def on_pre_enter(self, *args):
        Window.bind(on_keyboard=self.events_program)

    def events_program(self, instance, keyboard, keycode, text, modifiers):
        if keyboard in (1001, 27):
            self.go_to_login()
        return True

    def go_to_login(self, *args):
        self.manager.current = 'start_screen'

    def init_registration(self):
        self.email = self.ids.register_screen_email.text
        self.login = self.ids.register_screen_login.text
        self.password = self.ids.register_screen_password.text
        self.password_2 = self.ids.register_screen_password_2.text

        if not self.email:
            return

        if not self.login:
            return

        if not self.password:
            return

        if not self.password_2:
            return

        if '@' not in self.email or '.' not in self.email:
            return

        if len(self.login) < 6:
            self.ids.register_screen_error.text = 'Login length should be at least 6'
            return

        if not self.password_2 == self.password:
            self.ids.register_screen_error.text = 'Passwords do not match'
            return

        val, err = check_password(self.password)
        if not val:
            self.ids.register_screen_error.text = err
            return

        data = dumps({'email': self.email})
        self.register_request = UrlRequest(url=URL + '/api/initiate_registration', req_body=data,
                                           on_success=self.go_to_complete_register, on_failure=self.register_failure,
                                           method='POST', req_headers=headers, verify=False)

    def go_to_complete_register(self, *args):
        result = self.register_request.result
        if result['status'] == 'OK':
            self.manager.login = self.login
            self.manager.password = self.password
            self.manager.email = self.email
            self.manager.current = 'confirm_email'

    def register_failure(self, i, failure_data):
        error = failure_data['error']
        if error == 'Send error':
            self.ids.register_screen_error.text = 'Send token error. Check email and try again'
        else:
            self.ids.register_screen_error.text = error
        return


class RebootScreen(Screen, Logo):
    def __init__(self, **kwargs):
        super(RebootScreen, self).__init__(**kwargs)
        Window.bind(on_keyboard=self.events_program)

    def on_pre_enter(self, *args):
        Window.bind(on_keyboard=self.events_program)

    def events_program(self, instance, keyboard, keycode, text, modifiers):
        if keyboard in (1001, 27):
            pass
        return True

    def app_exit(self, *args):
        sys.exit(0)


class ReadPrivateKey(Screen):
    def __init__(self, **kwargs):
        super(ReadPrivateKey, self).__init__(**kwargs)
        Window.bind(on_keyboard=self.events_program)

    def events_program(self, instance, keyboard, keycode, text, modifiers):
        if keyboard in (1001, 27):
            pass
        return True

    def on_pre_enter(self, *args):
        Window.bind(on_keyboard=self.events_program)
        self.ids.zbarcam.on_starting()

    def go_to_login(self, *args):
        self.manager.current = 'start_screen'

    def on_read(self, key):
        if not key:
            return
        suc = False
        try:
            key = key[0].data
            suc = check_key(key)
        except Exception as e:
            suc = False
        if suc:
            self.ids.zbarcam.stop()
            with open(os.path.join(shared_dir, 'login', 'credentials.json'), 'w', encoding='utf-8') as f:
                credentials_temp = load(open(os.path.join(shared_dir, 'temp', "temp_login")))
                data = {'login': credentials_temp['login'], 'password': credentials_temp['password'],
                        'public_key': credentials_temp['public_key'], 'username': credentials_temp['username']}
                f.write(dumps(data))

            hashed_login = hashlib.sha512(credentials_temp['login'].encode('utf-8')).hexdigest()
            key = int(key)
            key = bytes.fromhex(hex(key).replace('0x', ''))
            key_s = key.decode('utf-8')
            with open(os.path.join(shared_dir, 'login', hashed_login + ".pem"), "w") as f:
                f.write(key_s)
            self.manager.current = 'reboot_app'
        return True


class StartScreen(Screen, Logo):
    def __init__(self, **kwargs):
        super(StartScreen, self).__init__(**kwargs)
        Window.bind(on_keyboard=self.events_program)

    def on_pre_enter(self, *args):
        Window.bind(on_keyboard=self.events_program)

    def events_program(self, instance, keyboard, keycode, text, modifiers):
        if keyboard in (1001, 27):
            pass
        return True

    def on_reg(self):
        if not check_storage_permission():
            request_storage_permission()
            return
        check_path()
        self.manager.current = 'registration'

    def on_sign_in(self):
        if not check_storage_permission():
            request_storage_permission()
            return
        check_path()
        self.login = self.ids.start_screen_login.text
        self.password = self.ids.start_screen_password.text
        if not self.login:
            return
        if not self.password:
            return

        data = {'login': self.login, 'password': self.password}
        data = dumps(data)
        self.login_request = UrlRequest(url=URL + '/api/get_user_data', req_body=data, on_success=self.get_login_data,
                                        method='GET', req_headers=headers, verify=False, on_failure=self.invalid_data)

    def get_login_data(self, *args):
        result = self.login_request.result
        if result is None:
            return
        if result['status'] != 'OK':
            return
        login_data = {'login': self.login, 'password': self.password, 'username': result['data']['username'],
                      'public_key': result['data']['public_key']}
        with open(os.path.join(shared_dir, 'temp', 'temp_login'), 'w', encoding='utf-8') as f:
            f.write(dumps(login_data))
        self.manager.current = 'read_key'

    def invalid_data(self, *args):
        result = self.login_request.result
        if result is None:
            return
        self.ids.login_error.text = result['error']


class ConfirmEmailScreen(Screen, Logo):
    def __init__(self, **kwargs):
        super(ConfirmEmailScreen, self).__init__(**kwargs)
        self.time = 0
        self.clock = None
        self.public_pem = None
        self.register_complete_request = None
        Window.bind(on_keyboard=self.events_program)

    def events_program(self, instance, keyboard, keycode, text, modifiers):
        if keyboard in (1001, 27):
            self.go_to_registration()
        return True

    def go_to_registration(self, *args):
        self.manager.current = 'registration'

    def update_timer(self, *args):
        self.time += 1
        if self.time > 59:
            self.ids.confirm_email_screen_timer.text = 'Token has expired'
            self.ids.confirm_email_screen_button.disabled = True
            self.clock.cancel()
        else:
            self.ids.confirm_email_screen_timer.text = f'Token expires in {60 - self.time} second'

    def on_pre_enter(self, *args):
        Window.bind(on_keyboard=self.events_program)
        self.ids.confirm_email_screen_button.disabled = False
        self.ids.confirm_email_screen_email.text = 'email ' + self.manager.email
        self.time = 0
        self.clock = Clock.schedule_interval(self.update_timer, 1)

    def on_registration_complete(self):
        token = self.ids.confirm_email_screen_token.text
        if not token:
            return
        if len(token) != 7:
            return

        hashed_login = hashlib.sha512(self.manager.login.encode('utf-8')).hexdigest()

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(self.manager.password.encode("utf-8"))
        )

        with open(os.path.join(shared_dir, 'login', hashed_login + ".pem"), "wb") as f:
            f.write(private_pem)

        self.public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        data = {'email': self.manager.email, 'login': self.manager.login, 'password': self.manager.password,
                'token': str(token), 'public_key': self.public_pem}
        data = dumps(data)
        self.register_complete_request = UrlRequest(url=URL + '/api/complete_registration', req_body=data,
                                                    on_success=self.success_complete,
                                                    on_failure=self.complete_error,
                                                    method='POST', req_headers=headers, verify=False)
        return

    def success_complete(self, i, *args):
        result = self.register_complete_request.result
        if result['status'] == 'OK':
            self.clock.cancel()
            with open(os.path.join(shared_dir, 'login', 'credentials.json'), 'w', encoding='utf-8') as f:
                data = dumps(
                    {'login': self.manager.login, 'password': self.manager.password, 'public_key': self.public_pem,
                     'username': result['username']})
                f.write(data)
        self.manager.current = 'register_info'

    def complete_error(self, i, failure):
        self.ids.confirm_email_screen_error.text = failure['error']


class ChatsScreen(Screen):
    def __init__(self, **kwargs):
        super(ChatsScreen, self).__init__(**kwargs)
        self.chats = None
        self.params = None
        self.update_chats_event = None
        self.chats_request = None

    def events_program(self, instance, keyboard, keycode, text, modifiers):
        if keyboard in (1001, 27):
            pass
        return True

    def go_to_create_chat(self, *args):
        self.manager.current = 'add_chat'

    def go_to_settings(self, *args):
        self.manager.current = 'settings_screen'

    def on_pre_enter(self, *args):
        Window.bind(on_keyboard=self.events_program)
        try:
            self.manager.current_chat['username']
            self.chats = None
        except Exception:
            pass
        with open(os.path.join(shared_dir, 'login', 'credentials.json'), 'r', encoding='utf-8') as f:
            data = f.read()
            self.params = loads(data)
            self.manager.params = self.params

        data = {'login': self.params['login'], 'password': self.params['password']}
        data = dumps(data)
        self.update_chats_event = Clock.schedule_interval(self.update_chats, 5)
        self.chats_request = UrlRequest(url=URL + '/api/get_user_chats', req_body=data,
                                        on_success=self.write_chats,
                                        method='GET', req_headers=headers, verify=False)

    def update_chats(self, *args):
        data = {'login': self.params['login'], 'password': self.params['password']}
        data = dumps(data)
        self.chats_request = UrlRequest(url=URL + '/api/get_user_chats', req_body=data,
                                        on_success=self.write_chats,
                                        method='GET', req_headers=headers, verify=False)

    def write_chats(self, *args):
        request = self.chats_request.result
        if request is None:
            return
        if request['status'] == 'OK':
            chats = request['chats']
            if self.chats != chats:
                self.chats = chats

                self.ids.chats_screen_chats.clear_widgets()
                for i in range(len(self.chats)):
                    if not os.path.exists(
                            os.path.join(shared_dir, 'avatars', chats[i]['username'].replace('@', '') + '.png')):
                        with open(os.path.join('data', 'img', 'ghost_user.png'), 'rb') as f:
                            img = f.read()
                        with open(os.path.join(shared_dir, 'avatars', chats[i]['username'].replace('@', '') + '.png'),
                                  'wb') as f:
                            f.write(img)
                    if not os.path.exists(
                            os.path.join(shared_dir, 'names', chats[i]['username'].replace('@', '') + '.name')):
                        with open(os.path.join(shared_dir, 'names', chats[i]['username'].replace('@', '') + '.name'),
                                  'w',
                                  encoding='utf-8') as f:
                            f.write(chats[i]['username'])

                    with open(os.path.join(shared_dir, 'names', chats[i]['username'].replace('@', '') + '.name'), 'r',
                              encoding='utf-8') as f:
                        name = f.read()
                    message = self.chats[i]['last_message']
                    message_text = 'Empty chat'
                    if message is not None:
                        message = decrypt_message(message)
                        if message['status'] == 'error':
                            continue
                        if message['type'] == 1:
                            message_text = message['data']
                    line = TwoLineAvatarIconListItem(text=name, secondary_text=message_text,
                                                     on_release=self.go_to_message)
                    line.add_widget(IconLeftWidget(
                        icon=os.path.join(shared_dir, 'avatars', chats[i]['username'].replace('@', '') + '.png'),
                        on_release=self.edit_chat))
                    if message is not None and message['sent_by'] == self.params['username'] and not message['viewed']:
                        line.add_widget(ImageRightWidget(
                            source=os.path.join('data', 'img', 'UnreadCircle.png')))
                    elif message is not None and message['sent_by'] != self.params['username'] \
                            and not message['viewed']:
                        count = self.chats[i]['unread_messages']
                        if count > 9:
                            count = '9+'
                        line.add_widget(ImageRightWidget(
                            source=os.path.join('data', 'img', f'UnreadCircleNumber{count}.png')))
                    self.ids.chats_screen_chats.add_widget(line)

    def go_to_message(self, click):
        chat = self.chats[len(self.chats) - self.ids.chats_screen_chats.children.index(click) - 1]
        with open(os.path.join(shared_dir, 'names', chat['username'].replace('@', '') + '.name'), 'r',
                  encoding='utf-8') as f:
            name = f.read()
        self.manager.current_chat = [chat, name]
        self.manager.current = 'messages'

    def edit_chat(self, click):
        item = self.ids.chats_screen_chats.children.index(click.parent.parent)
        chat = self.chats[len(self.chats) - item - 1]
        self.manager.current_chat = chat
        self.manager.current = 'edit_chat'

    def on_leave(self, *args):
        self.update_chats_event.cancel()


class AddChatScreen(Screen):
    def __init__(self, **kwargs):
        super(AddChatScreen, self).__init__(**kwargs)
        self.is_default_photo = True
        self.custom_photo = None
        self.photo_id = None
        self.username = None
        self.name_user = None
        self.create_chat_request = None
        self.get_key_request = None
        Window.bind(on_keyboard=self.events_program)

    def events_program(self, instance, keyboard, keycode, text, modifiers):
        if keyboard in (1001, 27):
            self.go_to_chats()
        return True

    def on_pre_enter(self, *args):
        Window.bind(on_keyboard=self.events_program)
        self.ids.create_chat_screen_name.text = ''
        self.ids.create_chat_screen_username.text = ''
        if self.manager.current_photo is not None:
            self.ids.create_chat_screen_image.source = self.manager.current_photo
        else:
            self.ids.create_chat_screen_image.source = os.path.join('data', 'img', 'ghost_user.png')

    def go_to_chats(self, *args):
        self.manager.current = 'chats'

    def on_upload_photo(self, *args):
        if not check_storage_permission():
            request_storage_permission()
            return

        filechooser.open_file(on_selection=self.select_path, filters=fil_avail_profile_ext_plyer,
                              path=picture_path)

    def select_path(self, path):
        if not path:
            return
        self.path = path[0]
        try:
            self.path.split('.')
        except AttributeError:
            return
        if self.path.split('.')[-1] in ['png', 'jpg', 'jpeg']:
            self.photo_id = str(randint(1000000, 9999999))
            self.path = make_avatar(self.path, os.path.join(shared_dir, 'temp', self.photo_id + '.png'))
            self.is_default_photo = False
            self.custom_photo = self.path
            self.ids.create_chat_screen_image.source = self.custom_photo

    def on_create_chat(self, *args):
        self.username = self.ids.create_chat_screen_username.text
        self.name_user = self.ids.create_chat_screen_name.text
        if self.username[0] != '@':
            self.ids.create_chat_screen_error.text = 'Username should start with @'
            return
        if len(self.username) != 9:
            self.ids.create_chat_screen_error.text = 'Incorrect username'
            return
        if not self.name_user:
            self.ids.create_chat_screen_error.text = 'Enter name'

        data = {'login': self.manager.params['login'], 'password': self.manager.params['password'],
                'user': self.username}
        data = dumps(data)

        self.create_chat_request = UrlRequest(url=URL + '/api/create_chat', req_body=data,
                                              on_success=self.success_chat_create, on_failure=self.chat_create_failure,
                                              method='POST', req_headers=headers, verify=False)

    def success_chat_create(self, *args):
        if self.is_default_photo:
            with open(os.path.join('data', 'img', 'ghost_user.png'), 'rb') as f:
                img = f.read()
            with open(os.path.join(shared_dir, 'avatars', self.username.replace('@', '') + '.png'), 'wb') as f:
                f.write(img)
        else:
            with open(self.custom_photo, 'rb') as f:
                img = f.read()
            with open(os.path.join(shared_dir, 'avatars', self.username.replace('@', '') + '.png'), 'wb') as f:
                f.write(img)
            os.remove(self.custom_photo)
        with open(os.path.join(shared_dir, 'names', self.username.replace('@', '') + '.name'), 'w',
                  encoding='utf-8') as f:
            f.write(self.name_user)

        data = {'login': self.manager.params['login'], 'password': self.manager.params['password'],
                'username': self.username}
        data = dumps(data)
        self.get_key_request = UrlRequest(url=URL + '/api/get_public_key', req_body=data,
                                          on_success=self.success_get_key, method='GET', req_headers=headers,
                                          verify=False)

        self.manager.current = 'chats'

    def chat_create_failure(self, i, failure):
        pass

    def success_get_key(self, *args):
        request = self.get_key_request.result
        if request is None:
            return
        if request['status'] == 'OK':
            key = request['public_key']
            with open(os.path.join(shared_dir, 'keys', self.username.replace('@', '')), 'w', encoding='utf-8') as f:
                f.write(key)


class EditChatScreen(Screen):
    def __init__(self, **kwargs):
        super(EditChatScreen, self).__init__(**kwargs)
        self.is_default_photo = True
        self.custom_photo = None
        self.photo_id = None
        self.username = None
        self.name_user = None
        Window.bind(on_keyboard=self.events_program)

    def events_program(self, instance, keyboard, keycode, text, modifiers):
        if keyboard in (1001, 27):
            self.go_to_chats()
        return True

    def go_to_chats(self, *args):
        self.manager.current = 'chats'

    def on_pre_enter(self, *args):
        Window.bind(on_keyboard=self.events_program)
        chat = self.manager.current_chat
        with open(os.path.join(shared_dir, 'names', chat['username'].replace('@', '') + '.name'), 'r',
                  encoding='utf-8') as f:
            name = f.read()
        self.ids.create_chat_screen_name.text = name
        self.ids.create_chat_screen_username.text = chat['username']
        self.ids.create_chat_screen_image.source = os.path.join(shared_dir, 'avatars',
                                                                chat['username'].replace('@', '') + '.png')

    def on_upload_photo(self, *args):
        if not check_storage_permission():
            request_storage_permission()
            return

        filechooser.open_file(on_selection=self.select_path, filters=fil_avail_profile_ext_plyer,
                              path=picture_path)

    def select_path(self, path):
        if not path:
            return
        self.path = path[0]
        try:
            self.path.split('.')
        except AttributeError:
            return
        if self.path.split('.')[-1] in ['png', 'jpg', 'jpeg']:
            self.photo_id = str(randint(1000000, 9999999))
            self.path = make_avatar(self.path, os.path.join(shared_dir, 'temp', self.photo_id + '.png'))
            self.is_default_photo = False
            self.custom_photo = self.path
            self.ids.create_chat_screen_image.source = self.custom_photo

    def on_edit_chat(self, *args):
        self.username = self.ids.create_chat_screen_username.text
        self.name_user = self.ids.create_chat_screen_name.text
        if self.username[0] != '@':
            self.ids.create_chat_screen_error.text = 'Username should start with @'
            return
        if len(self.username) != 9:
            self.ids.create_chat_screen_error.text = 'Incorrect username'
            return
        if not self.name_user:
            self.ids.create_chat_screen_error.text = 'Enter name'

        if self.is_default_photo:
            with open(os.path.join('data', 'img', 'ghost_user.png'), 'rb') as f:
                img = f.read()
            with open(os.path.join(shared_dir, 'avatars', self.username.replace('@', '') + '.png'), 'wb') as f:
                f.write(img)
        else:
            with open(self.custom_photo, 'rb') as f:
                img = f.read()
            with open(os.path.join(shared_dir, 'avatars', self.username.replace('@', '') + '.png'), 'wb') as f:
                f.write(img)
            os.remove(self.custom_photo)
        with open(os.path.join(shared_dir, 'names', self.username.replace('@', '') + '.name'), 'w',
                  encoding='utf-8') as f:
            f.write(self.name_user)
        self.manager.current = 'chats'


class MessageScreen(Screen):
    def __init__(self, **kwargs):
        super(MessageScreen, self).__init__(**kwargs)
        self.get_all_message_request = None
        self.all_messages = None
        self.decrypt_messages = None
        self.update_messages_event = None
        self.old_decrypt_messages = None
        self.chat = None
        self.message_text = None
        self.message_type = None
        self.encrypt_message = None
        self.send_message_request = None
        Window.bind(on_keyboard=self.events_program)

    def events_program(self, instance, keyboard, keycode, text, modifiers):
        if keyboard in (1001, 27):
            self.go_to_chats()
        return True

    def go_to_chats(self, *args):
        self.manager.current = 'chats'

    def on_pre_enter(self, *args):
        Window.bind(on_keyboard=self.events_program)
        self.chat = self.manager.current_chat[0]
        self.ids.toolbar.title = str(self.manager.current_chat[1])

        data = {'login': self.manager.params['login'], 'password': self.manager.params['password'],
                'chat_id': self.manager.current_chat[0]['chat_id']}
        data = dumps(data)
        self.get_all_message_request = UrlRequest(url=URL + '/api/get_all_messages', req_body=data,
                                                  on_success=self.success_get_all_message, method='GET',
                                                  req_headers=headers,
                                                  verify=False)

        self.update_messages_event = Clock.schedule_interval(self.update_messages, 5)

    def update_messages(self, *args):
        data = {'login': self.manager.params['login'], 'password': self.manager.params['password'],
                'chat_id': self.manager.current_chat[0]['chat_id']}
        data = dumps(data)
        self.get_all_message_request = UrlRequest(url=URL + '/api/get_all_messages', req_body=data,
                                                  on_success=self.success_get_all_message, method='GET',
                                                  req_headers=headers,
                                                  verify=False)

    def success_get_all_message(self, *args):
        result = self.get_all_message_request.result
        if result is None:
            return

        if result['status'] == 'OK':
            self.all_messages = result['messages']
            if not self.all_messages:
                return
            self.decrypt_messages = []
            for i in range(len(self.all_messages)):
                decrypt = decrypt_message(self.all_messages[i])
                self.decrypt_messages.append(decrypt)

            if self.decrypt_messages != self.old_decrypt_messages:
                self.old_decrypt_messages = self.decrypt_messages

                self.ids.messages_list.clear_widgets()

                for j in range(len(self.decrypt_messages)):
                    temp_message = self.decrypt_messages[j]
                    if temp_message['type'] == 1:
                        if temp_message['sent_by'] != self.manager.params['username']:
                            new_message = OtherMessageLabel(text=temp_message['data'], color_out=vievedOtherColor)
                            new_message.color_out = vievedOtherColor
                            new_message.ids.label.text_size = (None, None)
                            new_message.ids.label._label.refresh()
                            if new_message.ids.label._label.texture.size[0] > self.width * .8:
                                temp_size_x = self.width * .8
                            else:
                                temp_size_x = new_message.ids.label._label.texture.size[0] + dp(10)
                            new_message.ids.label.width = temp_size_x
                            new_message.ids.label._label.refresh()
                            new_message.ids.label.height = new_message.ids.label._label.texture.size[1]
                        else:

                            if not temp_message['viewed']:
                                new_message = MyMessageLabel(text=temp_message['data'], color_out=unviewedMyColor)
                            else:
                                new_message = MyMessageLabel(text=temp_message['data'], color_out=vievedMyColor)
                            new_message.ids.label.text_size = (None, None)
                            new_message.ids.label._label.refresh()
                            if new_message.ids.label._label.texture.size[0] > self.width * .8:
                                temp_size_x = self.width * .8
                            else:
                                temp_size_x = new_message.ids.label._label.texture.size[0] + dp(10)
                            new_message.ids.label.width = temp_size_x
                            new_message.ids.label._label.refresh()
                            new_message.ids.label.height = new_message.ids.label._label.texture.size[1]

                        self.ids.messages_list.add_widget(new_message)

                self.ids.text_test.scroll_to(self.ids.messages_list.children[0], animate=False)

    def on_send_message(self, *args):
        self.message_text = self.ids.message_input.text
        if not self.message_text:
            return
        self.message_type = 1

        if self.message_type == 1:
            self.encrypt_message = encrypt_message(1, self.message_text.encode('utf-8'), self.chat['chat_id'],
                                                   self.chat['username'])
            data = dumps(self.encrypt_message)
            self.send_message_request = UrlRequest(url=URL + '/api/send_message', req_body=data,
                                                   on_success=self.success_send_message, method='POST',
                                                   req_headers=headers,
                                                   verify=False)

    def success_send_message(self, *args):
        result = self.send_message_request.result
        if result is None:
            return
        if result['status'] == 'OK':
            if self.message_type == 1:
                new_message = MyMessageLabel(text=self.message_text, color_out=unviewedMyColor)
                new_message.ids.label.text_size = (None, None)
                new_message.ids.label._label.refresh()
                if new_message.ids.label._label.texture.size[0] > self.width * .8:
                    temp_size_x = self.width * .8
                else:
                    temp_size_x = new_message.ids.label._label.texture.size[0] + dp(10)
                new_message.ids.label.width = temp_size_x
                new_message.ids.label._label.refresh()
                new_message.ids.label.height = new_message.ids.label._label.texture.size[1]
                self.ids.messages_list.add_widget(new_message)
                self.ids.text_test.scroll_to(self.ids.messages_list.children[0], animate=False)
        self.clear_all_for_message()

    def clear_all_for_message(self):
        self.message_text = None
        self.message_type = None
        self.encrypt_message = None
        self.send_message_request = None
        self.ids.message_input.text = ''
        self.ids.message_input.focus = False

    def on_leave(self, *args):
        self.update_messages_event.cancel()


class RocketSenderApp(MDApp):
    def __init__(self, **kwargs):
        self.title = "RocketSender"
        super().__init__(**kwargs)

    def build(self):
        self.theme_cls.theme_style = 'Light'
        return Manager()


if __name__ == '__main__':
    RocketSenderApp().run()
