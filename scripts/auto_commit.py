import os
import subprocess
import json
import sys
from datetime import datetime, timedelta, timezone

def commit_changes(target_dir, branch_name):
    os.chdir(target_dir)
    
    # 读取上级目录生成的 commit_msgs.json
    msg_file = os.path.abspath("../commit_msgs.json")
    commit_msgs = {}
    if os.path.exists(msg_file):
        try:
            with open(msg_file, "r", encoding="utf-8") as f:
                commit_msgs = json.load(f)
        except Exception as e:
            print(f"[-] 读取 commit_msgs.json 失败: {e}")
            
    # 获取当前北京时间
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
        
        # 2. 智能匹配提交信息：支持精确路径、文件名、以及忽略后缀的 Stem 匹配
        msg = None
        if file_path in commit_msgs:
            msg = commit_msgs[file_path]
        else:
            for k, v in commit_msgs.items():
                k_filename = os.path.basename(k)
                k_stem = os.path.splitext(k_filename)[0]
                if k == file_path or k_filename == filename or k_stem == file_stem:
                    msg = v
                    break
        
        # 3. 拦截过于简陋或缺失的提交信息，强制升级为带时间的标准详细格式
        if not msg or msg.strip() == "更新" or msg.strip() == "Update":
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