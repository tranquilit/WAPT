import ast
import sys
from git import Repo

version = ''
filename = sys.argv[1]
with file(filename) as f:
    for line in f:
        if line.startswith('__version__'):
            version = ast.parse(line).body[0].value.s
            break

r = Repo('.',search_parent_directories=True)
rev_count = '%04d' % (r.active_branch.commit.count(),)

version = version +'.'+rev_count

print(version)
