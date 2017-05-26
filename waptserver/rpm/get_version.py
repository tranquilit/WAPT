import ast
import sys
version = ''
filename = sys.argv[1]
with file(filename) as f:
    for line in f:
        if line.startswith('__version__'):
            version = ast.parse(line).body[0].value.s
            break
print(version)
