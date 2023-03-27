import argparse
import time
import logging
import os
import queue
import threading
import signal
from github import Github
from github.GithubException import GithubException
import vt

current_repo_id = 0
SUSPECT_EXTENSIONS = ('.exe','.zip','.rar','.7z')

class StateTracker():
    def __init__(self) -> None:
        self.current_repo_id = 0
        self.repos_scanned = 0
        self.files_scanned = 0
        self.termination_requested = False

    def __str__(self) -> str:
        return f'Status: Current repo ID {self.current_repo_id}. Scanned {self.repos_scanned} repositories and {self.files_scanned} files.'

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--github', help="GitHub API key to use for hunting", default=os.getenv('GITHUB_TOKEN', None))
    parser.add_argument('-v', '--virustotal', help="VirusTotal API key to use for scanning and identifying", default=os.getenv('VT_TOKEN', None))
    parser.add_argument('-d', '--dry-run', help="Only notify on the console of malicious files found", action="store_true")
    parser.add_argument('-n', '--number-to-scan', help="Sets the max number of repos to scan before exiting. -1 for constant scanning.", default=-1, type=int)
    parser.add_argument('-s', '--since', help="Set the starting repository ID for the scan", required=False)
    return parser.parse_args()


def github_repo_file_grabber(file_queue: queue.Queue, status: StateTracker, config: argparse.Namespace):
    logger = logging.getLogger('GHHunter-RepoGrabber')
    logger.info('Starting repo grabber thread!')
    gh_api = Github(config.github)
    if config.since:
        since = int(config.since)
    else:
        since = None
    while not status.termination_requested:
        if since:
            repos = gh_api.get_repos(since=since)
        else:
            repos = gh_api.get_repos()
        for repo in repos:
            status.current_repo_id = repo.id
            try:
                files = repo.get_contents(path="/")
            except GithubException:
                logger.warn(f'Got Exception for repo {repo.name}')
                continue
            status.repos_scanned += 1
            for file in files:
                if file.name.endswith(SUSPECT_EXTENSIONS):
                    logger.info(f'Found suspect file {file.name} in repo {repo.id}')
                    message = (repo.id, file.sha, file.download_url)
                    file_queue.put(message)
            if status.termination_requested:
                break


def vt_submitter(file_queue: queue.Queue, status: StateTracker, config: argparse.Namespace):
    logger = logging.getLogger('GHHunter-VTSubmitter')
    logger.info('Starting VT Submitter thread!')
    vt_client = vt.Client(config.virustotal)
    while not status.termination_requested:
        try:
            file = file_queue.get_nowait()
        except queue.Empty:
            time.sleep(1)
            continue
        try:
            status.files_scanned += 1
            report = vt_client.get_object(f"/files/{file[1]}")
        except vt.error.APIError as apierr:
            if apierr.args[0] == "NotFoundError":
                logger.info('File not found on VT')
            continue
        if report.last_analysis_stats['malicious'] != 0:
            logger.warning(f'Found potentially malicious file at {file[2]}')


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('GHHunterMain')
    config = parse_args()
    logger.info(f'Running with config: {config}')
    file_queue = queue.Queue(maxsize=100)
    status = StateTracker()
    grabber_thread = threading.Thread(target=github_repo_file_grabber, args=[file_queue, status, config])
    submitter_thread = threading.Thread(target=vt_submitter, args=[file_queue, status, config])
    grabber_thread.start()
    submitter_thread.start()
    while not status.termination_requested:
        time.sleep(30)
        logger.info(str(status))
