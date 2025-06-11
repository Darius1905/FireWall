from gui.siem_gui import SIEMGuiApp
import tkinter as tk
from modules.FireWallSsh.firewall_auto import run

if __name__ == '__main__':
    root = tk.Tk()
    app = SIEMGuiApp(root)
    root.mainloop()
    run()
