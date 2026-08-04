import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

def commit_changes(target_dir, branch_name):
    os.chdir(target_dir)
    
    # 直接读取根目录下的 CHANGES.md
    changes_file = os.path.abspath("../CHANGES.md")
    changes_lines = []
    if os.path.exists(changes_file):
        try:
            with open(changes_file, "r", encoding="utf-8") as f:
                changes_lines = f.readlines()
        except Exception as e:
            print(f"[-] 读取 CHANGES.md 失败: {e}")
            
    # 获取当前北京时间作为兜底
    tz = timezone(timedelta(hours=8))
    now = datetime.now(tz)
    time_str = now.strftime("%Y年%m月%d日 %H:%M:%S")
    
    # 获取当前 git 状态
    status_output = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True).stdout
    lines = status_output.strip().split("\n")
    
    has_changes = False
    for line in lines:
        if not line.strip():
            continue
        file_path = line[3:].strip()
        if file_path.startswith('"') and file_path.endswith('"'):
            file_path = file_path[1:-1]
            
        has_changes = True
        # 1. 逐个文件 git add
        subprocess.run(["git", "add", file_path], check=True)
        
        filename = os.path.basename(file_path)
        file_stem = os.path.splitext(filename)[0] # 获取不带后缀的主干名（如 adblock, china）
        
        # 2. 从 CHANGES.md 中提取与该文件相关的描述信息
        msg = None
        for change_line in changes_lines:
            # 只要这一行包含了该文件名或主干名，就认为是要找的描述
            if filename in change_line or file_stem in change_line:
                cleaned = change_line.strip("#*- \t").strip()
                if cleaned and len(cleaned) > 2:
                    msg = cleaned
                    break
                    
        # 3. 兜底逻辑：如果 CHANGES.md 里没找到对应说明，则组合默认带时间的名称
        if not msg or msg == "更新" or msg == "Update":
            msg = f"{time_str} - 更新 {filename}"
            
        print(f"[*] 提交 [{file_path}] -> 消息: {msg}")
        # 4. 逐个文件执行 git commit
        subprocess.run(["git", "commit", "-m", msg], check=True)
        
    if has_changes:
        subprocess.run(["git", "push", "origin", f"HEAD:{branch_name}"], check=True)
        print(f"[+] 分支 {branch_name} 推送成功！")
    else:
        print(f"[-] 分支 {branch_name} 无变更，跳过推送。")
        
    os.chdir("..")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python auto_commit.py <目标目录> <分支名>")
        sys.exit(1)
    commit_changes(sys.argv[1], sys.argv[2])