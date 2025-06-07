import platform
from modules.FireWall import fireWall_macos, fireWall_window, fireWall_linux


def run():
    os_type = platform.system()
    print(f"[INFO] Detected OS: {os_type}")

    if os_type == 'Linux':
        fireWall_linux.run()
    elif os_type == 'Windows':  # ✅ Sửa tại đây
        fireWall_window.run()
    elif os_type == "Darwin":
        fireWall_macos.run()
    else:
        print('❌ This operating system is not supported.')


if __name__ == "__main__":
    run()
