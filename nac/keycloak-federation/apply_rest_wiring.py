import sys

path = "/etc/freeradius/3.0/sites-enabled/default"
with open(path) as f:
    content = f.read()

anchor1 = "\t#  raddb/mods-config/files/authorize\n\tfiles\n"
insert1 = (
    "\n"
    "\t#  ZTA: force Keycloak REST auth instead of local files/pap\n"
    "\tif (&User-Password) {\n"
    "\t\tupdate control {\n"
    "\t\t\tAuth-Type := REST\n"
    "\t\t}\n"
    "\t}\n"
)
c1 = content.count(anchor1)
if c1 != 1:
    print(f"ERROR: anchor1 occurrences = {c1}, expected 1. Aborting, no changes made.")
    sys.exit(1)

anchor2 = "\tAuth-Type PAP {\n\t\tpap\n\t}\n"
insert2 = (
    "\n"
    "\tAuth-Type REST {\n"
    "\t\tkeycloak_nac\n"
    "\t\tif (notfound || invalid || expired || disabled) {\n"
    "\t\t\treject\n"
    "\t\t}\n"
    "\t}\n"
)
c2 = content.count(anchor2)
if c2 != 1:
    print(f"ERROR: anchor2 occurrences = {c2}, expected 1. Aborting, no changes made.")
    sys.exit(1)

idx1 = content.find(anchor1)
content = content[:idx1] + anchor1 + insert1 + content[idx1+len(anchor1):]

idx2 = content.find(anchor2)
content = content[:idx2+len(anchor2)] + insert2 + content[idx2+len(anchor2):]

with open(path, "w") as f:
    f.write(content)

print("Applied both edits cleanly.")
