import dearpygui.dearpygui as dpg
from winapi import select_folder_spec, select_file_spec
from algorithms import generate, sign, verify, encrypt, decrypt
import ctypes
import os
import webbrowser
from pyperclip import copy, paste
import json

user32 = ctypes.windll.user32
w, h = user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)
dpg.create_context()


def set_font_size():
    font_size = dpg.get_value("settings_font_size")
    dpg.set_global_font_scale(font_size)


def dpg_select_folder_wrapper(component):
    def dpg_select_folder():
        save_at = select_folder_spec()
        if not save_at:
            return
        dpg.set_value(component, save_at)

    return dpg_select_folder


def dpg_select_file_wrapper(component):
    def dpg_select_file():
        save_at = select_file_spec()
        if not save_at:
            return
        dpg.set_value(component, save_at)

    return dpg_select_file


def encrypt_select_file():
    save_at = select_file_spec()
    if not save_at:
        return
    dpg.set_value("encrypt_message", save_at)
    folder, filename = os.path.split(save_at)
    filename, extension = os.path.splitext(filename)
    encrypted_save_at = os.path.join(folder, f"{filename}_encrypted.json")
    dpg.set_value("encrypt_save_at", encrypted_save_at)


def decrypt_select_file():
    save_at = select_file_spec()
    if not save_at:
        return
    dpg.set_value("decrypt_message", save_at)
    folder, filename = os.path.split(save_at)
    filename, extension = os.path.splitext(filename)
    if not filename.endswith("_encrypted"):
        return
    filename = filename.removesuffix("_encrypted")
    decrypted_save_at = os.path.join(folder, f"{filename}.txt")
    dpg.set_value("decrypt_save_at", decrypted_save_at)


def generate_gui():
    complexity = int(dpg.get_value("generate_complexity"))
    keys_name = dpg.get_value("generate_keys_name")
    generate_open = dpg.get_value("generate_open")
    save_at = dpg.get_value("generate_save_at")
    if not keys_name:
        dpg.set_value("message", "The name of key pairs cannot be empty.")
        dpg.show_item("banner")
        return
    if not (save_at and os.path.isdir(save_at)):
        dpg.set_value("message", "The folder to save key pairs doesn't exist.")
        dpg.show_item("banner")
        return
    private_key, public_key = generate(complexity)
    with open(os.path.join(save_at, f"{keys_name}_private.txt"), "wb") as f:
        f.write(private_key)
    with open(os.path.join(save_at, f"{keys_name}_public.txt"), "wb") as f:
        f.write(public_key)
    if generate_open:
        webbrowser.open(save_at)
    else:
        dpg.set_value("message", "Succeed.")
        dpg.show_item("banner")


def dpg_copy_wrapper(component):
    def dpg_copy():
        value = dpg.get_value(component)
        copy(value)
        dpg.set_value("message", f"Successfully copied the value of {component}.")
        dpg.show_item("banner")

    return dpg_copy


def dpg_paste_wrapper(component):
    def dpg_paste():
        dpg.set_value(component, paste())

    return dpg_paste


def scan_gui():
    message_fp = dpg.get_value("sign_message")
    if not (message_fp and os.path.isfile(message_fp)):
        dpg.set_value("message", "Message doesn't exist.")
        dpg.show_item("banner")
        return
    private_key_fp = dpg.get_value("sign_private_key")
    if not (private_key_fp and os.path.isfile(private_key_fp)):
        dpg.set_value("message", "Private key doesn't exist.")
        dpg.show_item("banner")
        return
    with open(message_fp, "rb") as f:
        message = f.read()
    with open(private_key_fp, "rb") as f:
        private_key = f.read()
    signature = sign(message, private_key)
    if signature:
        dpg.set_value("sign_signature", signature)
    else:
        dpg.set_value("message", "The private key is invalid.")
        dpg.show_item("banner")


def set_font_size_mouse(_, direction):
    if dpg.is_mouse_button_down(dpg.mvMouseButton_Middle):  # 0-Left, 1-Right, 2-Wheel
        dpg.set_value("settings_font_size", 1)
        dpg.set_global_font_scale(1)
    elif dpg.is_key_down(dpg.mvKey_Control):
        font_size = dpg.get_value("settings_font_size")
        font_size = round(max(0.1, font_size + 0.1 * direction), 1)
        dpg.set_value("settings_font_size", font_size)
        dpg.set_global_font_scale(font_size)


def verify_gui():
    message_fp = dpg.get_value("verify_message")
    if not (message_fp and os.path.isfile(message_fp)):
        dpg.set_value("message", "Message doesn't exist.")
        dpg.show_item("banner")
        return
    public_key_fp = dpg.get_value("verify_public_key")
    if not (public_key_fp and os.path.isfile(public_key_fp)):
        dpg.set_value("message", "Public key doesn't exist.")
        dpg.show_item("banner")
        return
    signature = dpg.get_value("verify_signature")
    if not signature:
        dpg.set_value("message", "Signature is empty.")
        dpg.show_item("banner")
        return
    with open(message_fp, "rb") as f:
        message = f.read()
    with open(public_key_fp, "rb") as f:
        public_key = f.read()
    is_valid = verify(message, signature, public_key)
    if is_valid:
        dpg.set_value("message", "The signature is valid.")
    else:
        dpg.set_value("message", "The signature is not valid.")
    dpg.show_item("banner")




with dpg.window(tag="banner", pos=(int(0.05 * w), int(0.1 * h)), show=False,
                no_collapse=True, width=int(0.4 * w), height=int(0.2 * h),
                label="Message"):
    dpg.add_text(tag="message", wrap=0)

with dpg.window(tag="main_window"):
    with dpg.group():
        dpg.add_text("Backdoor Detection GUI")
        dpg.add_spacer(height=int(0.02 * h))

    with dpg.collapsing_header(label="Settings"):
        dpg.add_input_float(format="%.1f", step=0.1, label="Font size", default_value=1.2,
                            tag="settings_font_size", callback=set_font_size)
        dpg.add_text("Shortcut: Press \"Ctrl\" while mouse scroll up (+) and down (-). "
                     "Press mouse wheel to reset as 1.",
                     wrap=0)
        dpg.add_spacer(height=int(0.02 * h))

    with dpg.collapsing_header(label="Instructions "):
        dpg.add_text("Q: Question marks in file/folder path?", wrap=0)
        dpg.add_text("A: If you see question marks, do not panic. It is "
                     "the display error because \"dearpygui\" uses ASCII charset "
                     "instead of UTF-8 and does not support display of non-latin "
                     "languages. If your file path includes non-latin characters, "
                     "this error occur. However, we use UTF-8 string at backend, "
                     "so it will not cause a problem and your files are saved at "
                     "correct location.", wrap=0)
        dpg.add_text("""    Generating Keys:
        Click on the Generate Keys button to create a new RSA key pair.
        You can specify the key size and other parameters if needed.
        Save your public and private keys in a secure location. 
        \n\tThese will be essential for encryption and authentication.
                     
        Message Authentication:
        To authenticate a message, generate a hash of your message using SHA-512.
        Sign the hash using your private key to create a digital signature.
        Share the message along with the digital signature.

        Verifying Signatures:
        Paste the received message and digital signature into the designated areas.
        Use the sender's public key to verify the signature.
        Click on the Verify Signature" button to confirm the authenticity of the message.             

        Encrypting Messages:
        To encrypt a message, paste your plaintext message into the designated area.
        Select the recipient's public key from the dropdown menu.
        Click on the Encrypt button to generate the ciphertext.

        Decrypting Messages:
        Paste the ciphertext into the designated area.
        Use your private key to decrypt the message.
        Click on the Decrypt button to reveal the plaintext.
                     """, wrap=0)
        dpg.add_spacer(height=int(0.02 * h))

    
    with dpg.collapsing_header(label="Scan Files to check if its a Backdoor!"):
        dpg.add_text("Select a file to scan for potential backdoors.", wrap=0)
        dpg.add_spacer(height=int(0.02 * h))
        dpg.add_text("Select the file.", wrap=0)
        with dpg.group(horizontal=True):
            dpg.add_input_text(tag="file_input", readonly=True)
            dpg.add_button(label="Select file",
                        callback=dpg_select_file_wrapper("file_input"))
        dpg.add_button(label="Scan", callback=scan_gui)
        dpg.add_spacer(height=int(0.02 * h))
        dpg.add_text("Scan Result:")
        with dpg.group(horizontal=True):
            dpg.add_input_text(tag="sign_signature", readonly=True, multiline=True, default_value="The file contains malware and poses a threat to your computer.")
            dpg.add_button(label="Copy", callback=dpg_copy_wrapper("sign_signature"))
        dpg.add_spacer(height=int(0.02 * h))

with dpg.handler_registry():
    dpg.add_mouse_wheel_handler(callback=set_font_size_mouse)
    dpg.add_mouse_click_handler(callback=set_font_size_mouse)

dpg.create_viewport(title="Backdoor Detection GUI", width=int(0.5 * w), height=int(0.5 * h),
                    x_pos=int(00.5 * w), y_pos=int(0.25 * h))
dpg.setup_dearpygui()
dpg.show_viewport()
dpg.set_primary_window("main_window", True)
dpg.start_dearpygui()
dpg.destroy_context()
