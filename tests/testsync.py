
from waptpackage import *

remote_repo = WaptRemoteRepo(url='http://wapt.tranquilit.local/wapt')


def get_dist_package(remote_repo):
    """Do a diff of two packages files and downlad the most recent version of the waptckage"""

    local_repo = WaptLocalRepo('c:/wapt/cache')
    for package in local_repo.packages:
        remote_packages = remote_repo.packages_matching(package.package)
        if remote_packages and package < remote_packages[-1]:
            remote_repo.download_packages(package.package)
    local_repo.update_packages_index()

get_dist_package(remote_repo)