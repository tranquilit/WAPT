import os
import git

dir_path = os.path.dirname(os.path.realpath(__file__))

for path in os.listdir(dir_path):
    if os.path.isdir(path):
        try:
            git.Repo(path).git.pull()
        except:
            pass