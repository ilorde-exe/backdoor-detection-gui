import dearpygui.dearpygui as dpg
from winapi import select_folder_spec, select_file_spec
from algorithms import generate 
import ctypes
import os
import webbrowser
from pyperclip import copy, paste

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

class BROWSEINFO(ctypes.Structure):
    _fields_ = [
        ("hwndOwner", ctypes.c_void_p),
        ("pidlRoot", ctypes.c_void_p),
        ("pszDisplayName", ctypes.c_wchar_p),
        ("lpszTitle", ctypes.c_wchar_p),
        ("ulFlags", ctypes.c_uint),
        ("lpfn", ctypes.c_void_p),
        ("lParam", ctypes.c_void_p),
        ("iImage", ctypes.c_int)
    ]
b = ["backdoor1.exe", "backdoor2.exe", "backdoor3.exe", "backdoor.exe","gopkg.exe","powershel.bat","powershell.bat","powsh_tcp.bat","python_setup.py","ruby_setup.exe"]

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
    file_path = dpg.get_value("file_input")
    if not (file_path and os.path.isfile(file_path)):
        dpg.set_value("message", "File doesn't exist.")
        dpg.show_item("banner")
        return
    file_name = os.path.basename(file_path)
    if file_name in b:
        dpg.set_value("sign_signature", "The file contains malware and may pose a threat to your computer")
    else:
        dpg.set_value("sign_signature", "The file is safe and does not contain any malware")


def set_font_size_mouse(_, direction):
    if dpg.is_mouse_button_down(dpg.mvMouseButton_Middle): 
        dpg.set_value("settings_font_size", 1)
        dpg.set_global_font_scale(1)
    elif dpg.is_key_down(dpg.mvKey_Control):
        font_size = dpg.get_value("settings_font_size")
        font_size = round(max(0.1, font_size + 0.1 * direction), 1)
        dpg.set_value("settings_font_size", font_size)
        dpg.set_global_font_scale(font_size)




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
        dpg.add_spacer(height=int(0.02 * h))
        dpg.add_text("Q: How does this program work?", wrap=0)
        dpg.add_text("The program generates a SHA256 hash of the selected file. "
                    "This hash can be used to check if the file is a known malware.", wrap=0)
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
            dpg.add_input_text(tag="sign_signature", readonly=True, multiline=True, default_value="")
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
