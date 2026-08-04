import os
import subprocess
import json
import sys

def commit_changes(target_dir, branch_name):
    os.chdir(target_dir)
    
    # 读取上级目录生成的 commit_msgs.json
    msg_file = os.path.abspath("../commit_msgs.json")
    commit_msgs = {}
    if os.path.exists(msg_file):
        with open(msg_file, "r", encoding="utf-8") as f:
            commit_msgs = json.load(f)
            
    # 获取当前 git 状态
    status_output = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True).stdout
    lines = status_output.strip().split("\n")
    
    has_changes = False
    for line in lines:
        if not line.strip():
            continue
        # 解析 git status 输出的文件路径（跳过状态前缀）
        file_path = line[3:].strip()
        if file_path.startswith('"') and file_path.endswith('"'):
            file_path = file_path[1:-1]
            
        has_changes = True
        # 1. 逐个文件 git add
        subprocess.run(["git", "add", file_path], check=True)
        
        # 2. 精准匹配对应文件的提交信息
        msg = commit_msgs.get(file_path)
        if not msg:
            filename = os.path.basename(file_path)
            msg = f"更新 {filename}"
            
        print(f"[*] 正在提交 [{file_path}] -> 消息: {msg}")
        # 3. 逐个文件执行 git commit
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