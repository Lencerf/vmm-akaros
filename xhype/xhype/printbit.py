RED = '\033[0;31m'
NC = '\033[0m'  # No Color
num = 0x88500
for i in range(63, 31, -1):
    print("{:3}".format(i), end="")
print()
for i in range(63, 31, -1):
    mask = 1 << i
    if num & mask > 0:
        print(RED+"{:3}".format(1)+NC, end="")
    else:
        print("{:3}".format(0), end="")

print("\n")
for i in range(31, -1, -1):
    print("{:3}".format(i), end="")
print()
for i in range(31, -1, -1):
    mask = 1 << i
    if num & mask > 0:
        print(RED+"{:3}".format(1)+NC, end="")
    else:
        print("{:3}".format(0), end="")
print()
