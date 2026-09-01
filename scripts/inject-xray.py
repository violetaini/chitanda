#!/usr/bin/env python3
import os
import sys
import shutil

def inject_xray(xray_dir, myxray_dir):
    print(f"[*] Injecting Chitanda protocol into Xray-core: {xray_dir}")
    proxy_dir = os.path.join(xray_dir, "proxy", "chitanda")
    os.makedirs(proxy_dir, exist_ok=True)
    
    # 1. Copy integration/xray/* into proxy/chitanda/
    src_dir = os.path.join(myxray_dir, "integration", "xray")
    for fname in os.listdir(src_dir):
        shutil.copy2(os.path.join(src_dir, fname), os.path.join(proxy_dir, fname))
        print(f"  [+] Copied {fname} -> proxy/chitanda/")
        
    # 2. Patch main/distro/all/all.go
    all_go = os.path.join(xray_dir, "main", "distro", "all", "all.go")
    if os.path.exists(all_go):
        with open(all_go, "r", encoding="utf-8") as f:
            content = f.read()
        if 'proxy/chitanda' not in content:
            content = content.replace(
                '_ "github.com/xtls/xray-core/proxy/vless/outbound"',
                '_ "github.com/xtls/xray-core/proxy/chitanda"\n\t_ "github.com/xtls/xray-core/proxy/vless/outbound"'
            )
            with open(all_go, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  [+] Patched {all_go} with proxy/chitanda registration")
            
    # 3. Patch go.mod
    go_mod = os.path.join(xray_dir, "go.mod")
    if os.path.exists(go_mod):
        with open(go_mod, "r", encoding="utf-8") as f:
            content = f.read()
        if 'myxray' not in content:
            abs_myxray = os.path.abspath(myxray_dir).replace('\\', '/')
            content += f"\nreplace chitanda => {abs_myxray}\n"
            content += "\nrequire chitanda v0.0.0-unpublished\n"
            with open(go_mod, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  [+] Patched {go_mod} with replace chitanda => {abs_myxray}")
            
    print("[*] Injection into Xray-core completed successfully!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python inject-xray.py <path_to_xray_repo> [path_to_myxray_repo]")
        sys.exit(1)
    xray_path = sys.argv[1]
    myxray_path = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inject_xray(xray_path, myxray_path)
