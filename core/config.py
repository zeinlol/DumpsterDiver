import re
from pathlib import Path

import yaml

# PATH = './'
# OUTFILE = ''
# REMOVE_FLAG = False
BASE_DIR = Path(__file__).parents[1]
CONFIG = yaml.safe_load(open(BASE_DIR.joinpath('config.yaml')))
BASE64_CHARS = CONFIG['base64_chars']
ARCHIVE_TYPES = CONFIG['archive_types']
EXCLUDED_FILES = CONFIG['excluded_files']
LOGFILE = CONFIG['logfile']
MIN_KEY_LENGTH = CONFIG['min_key_length']
MAX_KEY_LENGTH = CONFIG['max_key_length']
HIGH_ENTROPY_EDGE = CONFIG['high_entropy_edge']
MIN_PASS_LENGTH = CONFIG['min_pass_length']
MAX_PASS_LENGTH = CONFIG['max_pass_length']
PASSWORD_COMPLEXITY = CONFIG['password_complexity']
BAD_EXPRESSIONS = CONFIG['bad_expressions']
PASSWORD_REGEX = re.compile(r"['\">](.*?)['\"<]")
RULES = yaml.safe_load(open(BASE_DIR.joinpath('rules.yaml')))
