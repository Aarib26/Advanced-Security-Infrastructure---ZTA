import sys
path = sys.argv[1]
with open(path) as f:
    content = f.read()
ANCHOR = "\tfiles\n"
start = 0
n = 0
while True:
    idx = content.find(ANCHOR, start)
    if idx == -1:
        break
    n += 1
    print(f"--- Occurrence {n} at byte {idx} ---")
    print(content[max(0,idx-150):idx+150])
    print()
    start = idx + 1
