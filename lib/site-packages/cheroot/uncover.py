
def uncover(lineranges):
    p = [map(int, x.strip().split('-', 1)) for x in lineranges.split(',') if "-" in x]
    p = [(b - a, a, b) for a, b in p]
    p.sort()
    return p

def showall(lineranges):
    f = open("server.py", "rb").readlines()
    for r, a, b in uncover(lineranges):
        print((a, b))
        for i in range(a - 1, b + 1):
            print(f[i])
