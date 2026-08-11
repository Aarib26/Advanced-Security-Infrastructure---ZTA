import sys

path = "/etc/freeradius/3.0/sites-enabled/default"
with open(path) as f:
    content = f.read()

broken = "\tAuth-Type REST {\n\t\tkeycloak_nac\n\t\t\treject\n\t}\n"

good = (
    "\tAuth-Type REST {\n"
    "\t\tkeycloak_nac\n"
    "\t\tif (notfound || invalid || expired || disabled) {\n"
    "\t\t\treject\n"
    "\t\t}\n"
    "\t}\n"
)

count = content.count(broken)
print(f"Broken-block occurrences found: {count}")
if count != 1:
    print("Aborting — manual inspection needed, printing context instead")
    idx = content.find("Auth-Type REST")
    print(content[max(0,idx-50):idx+300])
    sys.exit(1)

content = content.replace(broken, good)
with open(path, "w") as f:
    f.write(content)
print("Fixed.")
