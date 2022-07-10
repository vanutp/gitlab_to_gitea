import os
import re

import psycopg2
from dotenv import load_dotenv
from psycopg2._psycopg import connection
from psycopg2.extras import DictCursor

load_dotenv()

GITEA_DB_URI = os.getenv('GITEA_DB_URI')
GITLAB_DB_URI = os.getenv('GITLAB_DB_URI')


def name_clean(name):
    new_name = name.replace(' ', '_')
    new_name = re.sub(r'[^a-zA-Z0-9_.-]', '-', new_name)

    if new_name.lower() == 'plugins':
        return new_name + '-user'

    return new_name


class Conn:
    gt_cn: connection
    gt_cur: DictCursor
    gl_cn: connection
    gl_cur: DictCursor

    def __init__(self):
        self.gt_cn = psycopg2.connect(GITEA_DB_URI)
        self.gt_cur = self.gt_cn.cursor(cursor_factory=DictCursor)
        self.gl_cn = psycopg2.connect(GITLAB_DB_URI)
        self.gl_cur = self.gl_cn.cursor(cursor_factory=DictCursor)


def get_full_namespace_path(db_groups: dict[int, dict], namespace_id: int):
    current_group = db_groups[namespace_id]
    full_path = current_group['path']
    while parent_id := current_group['parent_id']:
        current_group = db_groups[parent_id]
        full_path = current_group['path'] + '_' + full_path
    return name_clean(full_path)
