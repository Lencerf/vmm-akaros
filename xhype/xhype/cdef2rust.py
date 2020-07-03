import sys

str_define = "#define"

c_file_path = sys.argv[1]
start_line = int(sys.argv[2]) - 1
end_line = int(sys.argv[3])


def get_comment(line, start):
    start = 0
    while start < len(line) and not line[start:].startswith("/*"):
        start += 1
    end = start
    while end < len(line) and not line[end:].startswith("*/"):
        end += 1
    return line[start:end+2]


def get_word(line, start):
    while start < len(line) and line[start].isspace():
        start += 1
    end = start
    while not line[end].isspace():
        end += 1
    word = line[start:end]
    return word, end


with open(c_file_path) as f:
    lines = f.readlines()
    for line in lines[start_line:end_line]:
        if line.startswith(str_define):
            _, next_index = get_word(line, 0)
            name, next_index = get_word(line, next_index)
            value, next_index = get_word(line, next_index)
            comment = get_comment(line, next_index)
            print("pub const {}:u64 = {};{}".format(name, value, comment))
        else:
            print(line, end="")
