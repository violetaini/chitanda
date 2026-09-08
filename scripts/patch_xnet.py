#!/usr/bin/env python3
import os
import sys
import glob
import stat
import subprocess

PATCH_COMMON_TARGET = "\tCountError func(errType string)\n\n\t// Internal state, differs between wrapped and non-wrapped implementations."
PATCH_COMMON_REPLACE = "\tCountError func(errType string)\n\n\t// MaxDataPadding, if positive, enables pseudo-random padding on HTTP/2 DATA frames (RFC 7540).\n\t// Bounded in range [0, 255].\n\tMaxDataPadding int\n\n\t// Internal state, differs between wrapped and non-wrapped implementations."

PATCH_TRANSPORT_TARGET = """			allowed, err = cs.awaitFlowControl(len(remain))
			if err != nil {
				return err
			}
			cc.wmu.Lock()
			data := remain[:allowed]
			remain = remain[allowed:]
			sentEnd = sawEOF && len(remain) == 0 && !hasTrailers
			err = cc.fr.WriteData(cs.ID, sentEnd, data)"""

PATCH_TRANSPORT_REPLACE = """			targetPad := 0
			if cc.t.MaxDataPadding > 0 {
				maxPad := cc.t.MaxDataPadding
				if maxPad > 255 {
					maxPad = 255
				}
				minPad := 8
				if minPad > maxPad {
					minPad = maxPad
				}
				targetPad = minPad + int(time.Now().UnixNano()%(int64(maxPad-minPad+1)))
			}
			reqBytes := len(remain)
			if targetPad > 0 {
				reqBytes += targetPad + 1
			}
			allowed, err = cs.awaitFlowControl(reqBytes)
			if err != nil {
				return err
			}
			cc.wmu.Lock()
			var data, pad []byte
			if targetPad > 0 && allowed > int32(len(remain)+1) {
				data = remain
				remain = nil
				actualPad := int(allowed) - len(data) - 1
				if actualPad > targetPad {
					actualPad = targetPad
				}
				if actualPad > 255 {
					actualPad = 255
				}
				if actualPad > 0 {
					pad = make([]byte, actualPad)
				}
			} else {
				takeData := min(int(allowed), len(remain))
				data = remain[:takeData]
				remain = remain[takeData:]
			}
			actualUsed := len(data)
			if len(pad) > 0 {
				actualUsed += 1 + len(pad)
			}
			if unused := allowed - int32(actualUsed); unused > 0 {
				cc.mu.Lock()
				cs.flow.add(unused)
				if cs.flow.conn != nil {
					cs.flow.conn.add(unused)
				}
				cc.cond.Broadcast()
				cc.mu.Unlock()
			}
			sentEnd = sawEOF && len(remain) == 0 && !hasTrailers
			if len(pad) > 0 {
				err = cc.fr.WriteDataPadded(cs.ID, sentEnd, data, pad)
			} else {
				err = cc.fr.WriteData(cs.ID, sentEnd, data)
			}"""

def make_writable(filepath):
    mode = os.stat(filepath).st_mode
    os.chmod(filepath, mode | stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)

def patch_file(filepath, old, new):
    if not os.path.exists(filepath):
        return False
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    if new in content:
        print(f"  [=] Already patched: {filepath}")
        return True
    if old not in content:
        print(f"  [-] Target chunk not found in: {filepath}")
        return False
    make_writable(filepath)
    content = content.replace(old, new, 1)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  [+] Successfully patched: {filepath}")
    return True

def patch_all():
    p = subprocess.run(["go", "env", "GOMODCACHE"], capture_output=True, text=True)
    cache = p.stdout.strip()
    if not cache:
        print("[!] GOMODCACHE not found")
        return

    pattern_common = os.path.join(cache, "golang.org", "x", "net@*", "http2", "transport_common.go")
    pattern_transport = os.path.join(cache, "golang.org", "x", "net@*", "http2", "transport.go")

    files_common = glob.glob(pattern_common)
    files_transport = glob.glob(pattern_transport)
    print(f"[*] Found {len(files_common)} transport_common.go and {len(files_transport)} transport.go in GOMODCACHE")
    for f in files_common:
        patch_file(f, PATCH_COMMON_TARGET, PATCH_COMMON_REPLACE)
    for f in files_transport:
        patch_file(f, PATCH_TRANSPORT_TARGET, PATCH_TRANSPORT_REPLACE)

if __name__ == "__main__":
    patch_all()
