import platform
from modules.FireWallSsh import fireWall_linux, fireWall_window, fireWall_macos


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
