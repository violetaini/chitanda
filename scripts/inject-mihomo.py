#!/usr/bin/env python3
import os
import sys
import shutil

def inject_mihomo(mihomo_dir, chitanda_dir):
    print(f"[*] Injecting Chitanda adapter into Mihomo: {mihomo_dir}")
    adapter_dir = os.path.join(mihomo_dir, "adapter", "outbound")
    constant_dir = os.path.join(mihomo_dir, "constant")
    
    os.makedirs(adapter_dir, exist_ok=True)
    
    # 1. Copy chitanda.go into adapter/outbound/
    src_adapter = os.path.join(chitanda_dir, "integration", "mihomo", "chitanda.go")
    dst_adapter = os.path.join(adapter_dir, "chitanda.go")
    shutil.copy2(src_adapter, dst_adapter)
    print(f"  [+] Copied {src_adapter} -> {dst_adapter}")
    
    # 2. Patch constant/adapters.go
    adapters_go = os.path.join(constant_dir, "adapters.go")
    if os.path.exists(adapters_go):
        with open(adapters_go, "r", encoding="utf-8") as f:
            content = f.read()
        if 'Chitanda' not in content:
            # 1) Add Chitanda to const ( ... ) enum
            content = content.replace(
                '\tShadowsocks',
                '\tChitanda\n\tShadowsocks'
            )
            # 2) Add case Chitanda: return "Chitanda" in String()
            content = content.replace(
                'case Shadowsocks:',
                'case Chitanda:\n\t\treturn "Chitanda"\n\tcase Shadowsocks:'
            )
            with open(adapters_go, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  [+] Patched {adapters_go} with Chitanda enum and Stringer")
            
    # 3. Patch adapter/outbound/parser.go
    parser_go = os.path.join(adapter_dir, "parser.go")
    if os.path.exists(parser_go):
        with open(parser_go, "r", encoding="utf-8") as f:
            content = f.read()
        if 'Chitanda' not in content:
            target_hook = 'case C.Shadowsocks:'
            new_hook = '''case C.Chitanda, "chitanda":
		var opt ChitandaOption
		if err := decode(mapping, &opt); err != nil {
			return nil, err
		}
		return NewChitanda(opt)
	case C.Shadowsocks:'''
            content = content.replace(target_hook, new_hook)
            with open(parser_go, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  [+] Patched {parser_go} with Chitanda decoder")
            
    # 4. Patch go.mod
    go_mod = os.path.join(mihomo_dir, "go.mod")
    if os.path.exists(go_mod):
        with open(go_mod, "r", encoding="utf-8") as f:
            content = f.read()
        if 'chitanda' not in content:
            abs_chitanda = os.path.abspath(chitanda_dir).replace('\\', '/')
            content += f"\nreplace chitanda => {abs_chitanda}\n"
            content += "\nrequire chitanda v0.0.0-unpublished\n"
            with open(go_mod, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  [+] Patched {go_mod} with replace chitanda => {abs_chitanda}")
            
    print("[*] Injection into Mihomo completed successfully!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python inject-mihomo.py <path_to_mihomo_repo> [path_to_chitanda_repo]")
        sys.exit(1)
    mihomo_path = sys.argv[1]
    chitanda_path = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inject_mihomo(mihomo_path, chitanda_path)
