import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import os

# ---------------- 字库操作函数 ----------------
def get_gb2312_code(char):
    """返回汉字的GB2312编码两个字节"""
    try:
        gb = char.encode('gb2312')
        if len(gb) != 2:
            raise ValueError("非GB2312编码字符")
        return gb
    except Exception as e:
        raise ValueError(f"字符'{char}'无法转换为GB2312编码") from e

def read_hzk16(char, hzk16_path):
    gb = get_gb2312_code(char)
    area = gb[0] - 0xA0
    index = gb[1] - 0xA0
    if not (1 <= area <= 94 and 1 <= index <= 94):
        raise ValueError(f"字符'{char}'GB2312编码超出范围")
    offset = ((area - 1) * 94 + (index - 1)) * 32
    with open(hzk16_path, 'rb') as f:
        f.seek(offset)
        data = f.read(32)
        if len(data) != 32:
            raise IOError("字库文件数据不足")
    return data

def hzk16_to_bitmap(data):
    bitmap = [[0]*16 for _ in range(16)]
    for row in range(16):
        byte1 = data[row*2]
        byte2 = data[row*2+1]
        for bit in range(8):
            bitmap[row][bit] = (byte1 >> (7 - bit)) & 0x01
            bitmap[row][bit+8] = (byte2 >> (7 - bit)) & 0x01
    return bitmap

def hzk16_to_oled_format(data):
    bitmap = hzk16_to_bitmap(data)
    oled_data = [0]*32
    for col in range(16):
        for page in range(2):
            byte = 0
            for bit in range(8):
                row = page * 8 + bit
                byte |= (bitmap[row][col] << bit)
            oled_data[page*16 + col] = byte
    return oled_data

def data_to_c_code(char, oled_data):
    lines = []
    lines.append(f'\t"{char}",')
    lines.append("\t" + ",".join(f"0x{b:02X}" for b in oled_data[:16]) + ",")
    lines.append("\t" + ",".join(f"0x{b:02X}" for b in oled_data[16:]) + ",")
    return "\n".join(lines)

# ---------------- 字库生成与预览 ----------------
def generate_code():
    input_str = entry.get("1.0", tk.END).strip()
    if not input_str:
        messagebox.showwarning("提示", "请输入要生成的汉字字符串")
        return
    hzk16_path = hzk16_path_var.get()
    if not hzk16_path:
        messagebox.showwarning("提示", "请先选择字库文件")
        return
    filtered_chars = []
    for ch in input_str:
        try:
            gb = ch.encode("gb2312")
            if len(gb) == 2:
                filtered_chars.append(ch)
        except:
            continue
    if not filtered_chars:
        messagebox.showwarning("提示", "输入的内容没有有效的汉字")
        return
    unique_chars = "".join(dict.fromkeys(filtered_chars))
    output_text.delete(1.0, tk.END)
    try:
        output_text.insert(tk.END, "/*宽16像素，高16像素*/\n")
        output_text.insert(tk.END, "const ChineseCell_t OLED_CF16x16[] = {\n\n")
        for ch in unique_chars:
            data = read_hzk16(ch, hzk16_path)
            oled_data = hzk16_to_oled_format(data)
            code = data_to_c_code(ch, oled_data)
            output_text.insert(tk.END, code + "\n\n")
        output_text.insert(tk.END, "};\n")
        draw_preview(hzk16_path, text="@哇李哈哈")
    except Exception as e:
        messagebox.showerror("错误", f"生成失败: {e}")

def draw_preview(hzk16_path, text="@哇李哈哈"):
    """绘制文本预览，汉字用字库，非汉字统一显示为 '@'，大小统一16x16"""
    try:
        canvas.delete("all")  # 清空画布
        cell_size = 8  # 每个点放大倍数
        margin = 4     # 字间距
        font_color = "black"

        for idx, char in enumerate(text):
            x_offset = idx * (16 * cell_size + margin)
            try:
                if char == '@':
                    # 特殊处理 '@'
                    bitmap = [
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                    ]



                else:
                    # 尝试从字库读取汉字
                    data = read_hzk16(char, hzk16_path)
                    bitmap = hzk16_to_bitmap(data)
            except:
                # 非汉字且不是 '@'，用全黑块表示
                bitmap = [[1]*16 for _ in range(16)]

            for y in range(16):
                for x in range(16):
                    color = "black" if bitmap[y][x] else "white"
                    canvas.create_rectangle(
                        x_offset + x*cell_size,
                        y*cell_size,
                        x_offset + (x+1)*cell_size,
                        (y+1)*cell_size,
                        fill=color,
                        outline="gray"
                    )

        canvas.config(width=max(160, len(text)*(16*cell_size+margin)), height=16*cell_size)
    except Exception as e:
        messagebox.showerror("错误", f"预览失败: {e}")


# ---------------- 文件操作 ----------------
def scan_local_hzk16(data_folder="data"):
    # 文件夹不存在就创建
    if not os.path.exists(data_folder):
        os.makedirs(data_folder)
        return []  # 创建后暂时没有文件，返回空列表

    files = [os.path.join(data_folder, f)
             for f in os.listdir(data_folder)
             if os.path.isfile(os.path.join(data_folder, f)) and "hzk" in f.lower()]
    return files

def import_text_file():
    path = filedialog.askopenfilename(title="导入TXT文件", filetypes=[("Text files", "*.txt")])
    if path:
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(path, "r", encoding="gbk") as f:
                content = f.read()
        entry.delete("1.0", tk.END)
        entry.insert(tk.END, content)

def export_text_file():
    path = filedialog.asksaveasfilename(title="导出TXT文件", defaultextension=".txt",
                                        filetypes=[("Text files", "*.txt")])
    if path:
        content = output_text.get("1.0", tk.END).strip()
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        messagebox.showinfo("成功", f"已保存到 {path}")

# ---------------- GUI 搭建 ----------------
root = tk.Tk()
root.title("16x16 GB2312 汉字字库生成器")
root.geometry("750x750")
root.resizable(False, False)

style = ttk.Style()
style.theme_use("clam")
style.configure("TButton", font=("Microsoft YaHei", 11), padding=6, background="#4A90E2", foreground="white")
style.configure("TLabel", font=("Microsoft YaHei", 11))
style.configure("TEntry", font=("Microsoft YaHei", 12), padding=4)
style.configure("TMenubutton", font=("Microsoft YaHei", 11), padding=4)

# ---------- 输入区 ----------
frm_input = ttk.Frame(root, padding=10)
frm_input.pack(fill="x")
ttk.Label(frm_input, text="请输入汉字字符串：").pack(anchor="w")
entry = scrolledtext.ScrolledText(frm_input, width=80, height=5, font=("Microsoft YaHei", 12),
                                  bg="#FFFFFF", relief="solid", borderwidth=1)
entry.pack(fill="x", padx=8, pady=5)

# ---------- 文件操作区 ----------
frm_file = ttk.Frame(root, padding=10)
frm_file.pack(fill="x")
ttk.Label(frm_file, text="字库文件:").pack(side="left")

available_fonts = scan_local_hzk16("data")
font_names = [os.path.basename(f) for f in available_fonts]
hzk16_path_var = tk.StringVar(value=available_fonts[0] if available_fonts else "")
current_file_name_var = tk.StringVar(value=font_names[0] if font_names else "")

if available_fonts:
    combo = ttk.Combobox(frm_file, values=font_names, state="readonly", width=20,
                         textvariable=current_file_name_var)
    combo.current(0)
    combo.pack(side="left", padx=8)

    def on_combo_select(event):
        idx = combo.current()
        hzk16_path_var.set(available_fonts[idx])

    combo.bind("<<ComboboxSelected>>", on_combo_select)
else:
    ttk.Label(frm_file, text="未发现字库文件，请手动选择").pack(side="left", padx=8)

def select_hzk16_file():
    path = filedialog.askopenfilename(title="选择HZK16字库文件", filetypes=[("All files", "*.*")])
    if path:
        hzk16_path_var.set(path)
        current_file_name_var.set(os.path.basename(path))
        draw_preview(path, "@哇李哈哈")

ttk.Button(frm_file, text="选择字库文件", command=select_hzk16_file).pack(side="left", padx=8)
ttk.Button(frm_file, text="导入TXT", command=import_text_file).pack(side="left", padx=8)
ttk.Button(frm_file, text="导出TXT", command=export_text_file).pack(side="left", padx=8)

# ---------- 预览区 ----------
frm_preview = ttk.Frame(root, padding=10)
frm_preview.pack(fill="x")
ttk.Label(frm_preview, text="字库预览:").pack(anchor="w")
canvas = tk.Canvas(frm_preview, width=160, height=160, bg="white")
canvas.pack()

# ---------- 生成按钮 ----------
frm_btn = ttk.Frame(root, padding=10)
frm_btn.pack(fill="x")
ttk.Button(frm_btn, text="生成字库代码", command=generate_code).pack(pady=5)

# ---------- 输出区 ----------
frm_output = ttk.Frame(root, padding=10)
frm_output.pack(fill="both", expand=True)
ttk.Label(frm_output, text="by bilibili@哇李哈哈", font=("Microsoft YaHei", 10),
          foreground="gray").pack(side="bottom", anchor="e", padx=10, pady=2)
output_text = scrolledtext.ScrolledText(frm_output, width=80, height=20, font=("Consolas", 10),
                                        bg="#F9F9F9", relief="solid", borderwidth=1)
output_text.pack(fill="both", expand=True)

root.mainloop()
