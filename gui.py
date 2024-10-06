from pathlib import Path

# from tkinter import *
# Explicit imports to satisfy Flake8
from tkinter import Tk, Canvas, Entry, Text, Button, PhotoImage
import argparse


OUTPUT_PATH = Path(__file__).parent
ASSETS_PATH = OUTPUT_PATH / Path(r"C:\Users\USER\Documents\Kyonet\gui\build\assets\frame0")


def relative_to_assets(path: str) -> Path:
    return ASSETS_PATH / Path(path)


window = Tk()

window.geometry("745x505")
window.configure(bg = "#FFFFFF")


canvas = Canvas(
    window,
    bg = "#FFFFFF",
    height = 505,
    width = 745,
    bd = 0,
    highlightthickness = 0,
    relief = "ridge"
)

canvas.place(x = 0, y = 0)
canvas.create_rectangle(
    0.0,
    0.0,
    745.0,
    87.0,
    fill="#0077BC",
    outline="")

image_image_1 = PhotoImage(
    file=relative_to_assets("image_1.png"))
image_1 = canvas.create_image(
    109.0,
    132.0,
    image=image_image_1
)

image_image_2 = PhotoImage(
    file=relative_to_assets("image_2.png"))
image_2 = canvas.create_image(
    109.0,
    206.0,
    image=image_image_2
)

image_image_3 = PhotoImage(
    file=relative_to_assets("image_3.png"))
image_3 = canvas.create_image(
    109.0,
    354.0,
    image=image_image_3
)

image_image_4 = PhotoImage(
    file=relative_to_assets("image_4.png"))
image_4 = canvas.create_image(
    109.0,
    280.0,
    image=image_image_4
)

canvas.create_text(
    68.0,
    120.0,
    anchor="nw",
    text="Interface",
    fill="#FFFFFF",
    font=("Dangrek Regular", 20 * -1)
)

canvas.create_text(
    18.0,
    18.0,
    anchor="nw",
    text="KYONET",
    fill="#FFFFFF",
    font=("Dangrek Regular", 35 * -1)
)

canvas.create_text(
    70.0,
    192.0,
    anchor="nw",
    text="Target IP",
    fill="#FFFFFF",
    font=("Dangrek Regular", 20 * -1)
)

canvas.create_text(
    57.0,
    265.0,
    anchor="nw",
    text="Filter Src IP",
    fill="#FFFFFF",
    font=("Dangrek Regular", 20 * -1)
)

canvas.create_text(
    58.0,
    341.0,
    anchor="nw",
    text="Filter Dis IP",
    fill="#FFFFFF",
    font=("Dangrek Regular", 20 * -1)
)

button_image_1 = PhotoImage(file=relative_to_assets("button_1.png"))
button_1 = Button(
    image=button_image_1,
    borderwidth=0,
    highlightthickness=0,
    command=lambda: (entry_1.get(), entry_4.get(), entry_3.get(), entry_2.get()),
    relief="flat"
)
button_1.place(x=202.0, y=404.0, width=322.0, height=82.0)


entry_image_1 = PhotoImage(
    file=relative_to_assets("entry_1.png"))
entry_bg_1 = canvas.create_image(
    568.0,
    124.0,
    image=entry_image_1
)
entry_1 = Entry(
    bd=0,
    bg="#D9D9D9",
    fg="#000716",
    highlightthickness=0
)
entry_1.place(
    x=456.0,
    y=104.0,
    width=224.0,
    height=38.0
)

entry_image_2 = PhotoImage(
    file=relative_to_assets("entry_2.png"))
entry_bg_2 = canvas.create_image(
    568.0,
    350.0,
    image=entry_image_2
)
entry_2 = Entry(
    bd=0,
    bg="#D9D9D9",
    fg="#000716",
    highlightthickness=0
)
entry_2.place(
    x=456.0,
    y=330.0,
    width=224.0,
    height=38.0
)

entry_image_3 = PhotoImage(
    file=relative_to_assets("entry_3.png"))
entry_bg_3 = canvas.create_image(
    568.0,
    285.0,
    image=entry_image_3
)
entry_3 = Entry(
    bd=0,
    bg="#D9D9D9",
    fg="#000716",
    highlightthickness=0
)
entry_3.place(
    x=456.0,
    y=265.0,
    width=224.0,
    height=38.0
)

entry_image_4 = PhotoImage(
    file=relative_to_assets("entry_4.png"))
entry_bg_4 = canvas.create_image(
    568.0,
    212.0,
    image=entry_image_4
)
entry_4 = Entry(
    bd=0,
    bg="#D9D9D9",
    fg="#000716",
    highlightthickness=0
)
entry_4.place(
    x=456.0,
    y=192.0,
    width=224.0,
    height=38.0
)

image_image_5 = PhotoImage(
    file=relative_to_assets("image_5.png"))
image_5 = canvas.create_image(
    657.0,
    466.0,
    image=image_image_5
)

image_image_6 = PhotoImage(
    file=relative_to_assets("image_6.png"))
image_6 = canvas.create_image(
    185.0,
    45.0,
    image=image_image_6
)

image_image_7 = PhotoImage(
    file=relative_to_assets("image_7.png"))
image_7 = canvas.create_image(
    282.99870488795204,
    161.9702843427658,
    image=image_image_7
)

image_image_8 = PhotoImage(
    file=relative_to_assets("image_8.png"))
image_8 = canvas.create_image(
    284.9999844294516,
    312.80950248241425,
    image=image_image_8
)

image_image_9 = PhotoImage(
    file=relative_to_assets("image_9.png"))
image_9 = canvas.create_image(
    376.0,
    162.0,
    image=image_image_9
)

image_image_10 = PhotoImage(
    file=relative_to_assets("image_10.png"))
image_10 = canvas.create_image(
    372.0,
    313.0,
    image=image_image_10
)

window.resizable(False, False)
window.mainloop()
