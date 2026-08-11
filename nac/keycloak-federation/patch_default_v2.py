import sys

ANCHOR_1 = "\t#  raddb/mods-config/files/authorize\n\tfiles\n"
INSERT_1 = (
    "\n"
    "\t#  ZTA: force Keycloak REST auth instead of local files/pap\n"
    "\tif (&User-Password) {\n"
    "\t\tupdate control {\n"
    "\t\t\tAuth-Type := REST\n"
    "\t\t}\n"
    "\t}\n"
)

ANCHOR_2 = "\tAuth-Type PAP {\n\t\tpap\n\t}\n"
INSERT_2 = (
    "\n"
    "\tAuth-Type REST {\n"
    "\t\tkeycloak_nac\n"
    "\t\tif (ok) {\n"
    "\t\t\tupdate reply { }\n"
    "\t\t}\n"
    "\t\telse {\n"
    "\t\t\treject\n"
    "\t\t}\n"
    "\t}\n"
)

def main():
    path = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "--check"
    with open(path, "r") as f:
        content = f.read()

    idx1 = content.find(ANCHOR_1)
    if idx1 == -1:
        print("ERROR: anchor 1 not found"); sys.exit(1)
    count1 = content.count(ANCHOR_1)
    print(f"Anchor 1 found at byte {idx1}, occurrences: {count1}")

    idx2 = content.find(ANCHOR_2)
    if idx2 == -1:
        print("ERROR: anchor 2 not found"); sys.exit(1)
    count2 = content.count(ANCHOR_2)
    print(f"Anchor 2 found at byte {idx2}, occurrences: {count2}")

    if count1 != 1 or count2 != 1:
        print("WARNING: an anchor is not unique")
        if mode == "--apply":
            print("Refusing to apply. Aborting."); sys.exit(1)

    new_content = content[:idx1] + ANCHOR_1 + INSERT_1 + content[idx1+len(ANCHOR_1):]
    idx2_new = new_content.find(ANCHOR_2)
    new_content = new_content[:idx2_new+len(ANCHOR_2)] + INSERT_2 + new_content[idx2_new+len(ANCHOR_2):]

    if mode == "--check":
        print("\n=== Will insert after files/authorize anchor ===")
        print(INSERT_1)
        print("=== Will insert after Auth-Type PAP block ===")
        print(INSERT_2)
        print("\n(Nothing written. Re-run with --apply.)")
    elif mode == "--apply":
        with open(path, "w") as f:
            f.write(new_content)
        print(f"\nApplied. Wrote {len(new_content)} bytes.")
    else:
        print("Unknown mode"); sys.exit(1)

if __name__ == "__main__":
    main()
