import os
import random
import re
import string
import traceback
from datetime import datetime
from typing import Union

import dateutil.parser
import gitlab  # pip install python-gitlab
import gitlab.v4.objects
import psycopg2
import pygitea  # pip install pygitea (https://github.com/h44z/pygitea)
import requests
from dotenv import load_dotenv
from psycopg2._psycopg import connection
from psycopg2.extras import DictCursor
from tqdm import tqdm

SCRIPT_VERSION = '1.0'
GLOBAL_ERROR_COUNT = 0

load_dotenv()
#######################
# CONFIG SECTION START
#######################
GITLAB_URL = os.getenv('GITLAB_URL')
GITLAB_TOKEN = os.getenv('GITLAB_TOKEN')

# needed to clone the repositories, keep empty to try publickey (untested)
GITLAB_ADMIN_USER = os.getenv('GITLAB_ADMIN_USER')
GITLAB_ADMIN_PASS = os.getenv('GITLAB_ADMIN_PASS')

GITEA_URL = os.getenv('GITEA_URL')
GITEA_TOKEN = os.getenv('GITEA_TOKEN')

GITEA_DB_URI = os.getenv('GITEA_DB_URI')
GITLAB_DB_URI = os.getenv('GITLAB_DB_URI')


#######################
# CONFIG SECTION END
#######################

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


c = Conn()

user_id_map = {}
group_id_map = {}
project_id_map = {}


def to_tz_timestamp(iso: str):
    dt = datetime.fromisoformat(iso)
    return (dt + dt.tzinfo.utcoffset(dt)).timestamp()


def main():
    print_color(bcolors.HEADER, '---=== Gitlab to Gitea migration ===---')
    print('Version: ' + SCRIPT_VERSION)
    print()

    # private token or personal token authentication
    gl = gitlab.Gitlab(GITLAB_URL, private_token=GITLAB_TOKEN)
    gl.auth()
    assert (isinstance(gl.user, gitlab.v4.objects.CurrentUser))
    print_info('Connected to Gitlab, version: ' + str(gl.version()))

    gt = pygitea.API(GITEA_URL, token=GITEA_TOKEN)
    gt_version = gt.get('/version').json()
    print_info('Connected to Gitea, version: ' + str(gt_version['version']))

    # IMPORT USERS AND GROUPS
    import_users_groups(gl, gt)

    # IMPORT PROJECTS
    import_projects(gl, gt)

    import_events()

    print()
    if GLOBAL_ERROR_COUNT == 0:
        print_success('Migration finished with no errors!')
    else:
        print_error(f'Migration finished with {GLOBAL_ERROR_COUNT} errors!')


# 
# Data loading helpers for Gitea
#

def get_labels(gitea_api: pygitea, owner: string, repo: string) -> dict[str, dict]:
    existing_labels = {}
    label_response: requests.Response = gitea_api.get(f'/repos/{owner}/{repo}/labels')
    if label_response.ok:
        existing_labels = {x['name']: x for x in label_response.json()}
    else:
        print_error(f'Failed to load existing milestones for project {repo}! {label_response.text}')

    return existing_labels


def get_milestones(gitea_api: pygitea, owner: string, repo: string) -> dict[str, dict]:
    existing_milestones = {}
    milestone_response: requests.Response = gitea_api.get(f'/repos/{owner}/{repo}/milestones')
    if milestone_response.ok:
        existing_milestones = {x['title']: x for x in milestone_response.json()}
    else:
        print_error(f'Failed to load existing milestones for project {repo}! {milestone_response.text}')

    return existing_milestones


def get_teams(gitea_api: pygitea, orgname: string) -> list:
    existing_teams = {}
    team_response: requests.Response = gitea_api.get(f'/orgs/{orgname}/teams')
    if team_response.ok:
        existing_teams = team_response.json()
    else:
        print_error(f'Failed to load existing teams for organization {orgname}! {team_response.text}')

    return existing_teams


def get_team_members(gitea_api: pygitea, teamid: int) -> dict[str, dict]:
    existing_members = {}
    member_response: requests.Response = gitea_api.get(f'/teams/{teamid}/members')
    if member_response.ok:
        existing_members = {x['username']: x for x in member_response.json()}
    else:
        print_error(f'Failed to load existing members for team {teamid}! {member_response.text}')

    return existing_members


def get_namespace(gitea_api: pygitea, namespace_path: str) -> {}:
    result = None
    response: requests.Response = gitea_api.get(f'/users/{namespace_path}')
    if response.ok:
        result = response.json()

    # The api may return a 200 response, even if it's not a user but an org, let's try again!
    if result is None or result['id'] == 0:
        response: requests.Response = gitea_api.get(f'/orgs/{namespace_path}')
        if response.ok:
            result = response.json()
        else:
            print_error(f'Failed to load user or group {namespace_path}! {response.text}')

    return result


def get_user_keys(gitea_api: pygitea, username: string) -> dict[str, dict]:
    result = {}
    key_response: requests.Response = gitea_api.get('/users/' + username + '/keys')
    if key_response.ok:
        result = {x['title']: x for x in key_response.json()}
    else:
        print_error('Failed to load user keys for user ' + username + '! ' + key_response.text)

    return result


def user_exists(gitea_api: pygitea, username: string) -> Union[bool, dict]:
    user_response: requests.Response = gitea_api.get('/users/' + username)
    if user_response.ok:
        print_warning(f'User {username} does already exist in Gitea, skipping!')

    return user_response.json() if user_response.ok else False


def user_key_exists(gitea_api: pygitea, username: string, keyname: string) -> bool:
    existing_keys = get_user_keys(gitea_api, username)
    existing_key = existing_keys.get(keyname)

    if existing_key:
        print_warning(f'Public key {keyname} already exists for user {username}, skipping!')

    return existing_key is not None


def organization_exists(gitea_api: pygitea, orgname: string) -> bool:
    group_response: requests.Response = gitea_api.get(f'/orgs/{orgname}')
    if group_response.ok:
        print_warning(f'Group {orgname} does already exist in Gitea, skipping!')

    return group_response.ok


def member_exists(gitea_api: pygitea, username: string, teamid: int) -> bool:
    existing_members = get_team_members(gitea_api, teamid)
    existing_member = existing_members.get(username)

    if existing_member:
        print_warning(f'Member {username} is already in team {teamid}, skipping!')

    return existing_member is not None


def collaborator_exists(gitea_api: pygitea, owner: string, repo: string, username: string) -> bool:
    collaborator_response: requests.Response = gitea_api.get(f'/repos/{owner}/{repo}/collaborators/{username}')
    if collaborator_response.ok:
        print_warning(f'Collaborator {username} does already exist in Gitea, skipping!')

    return collaborator_response.ok


def repo_exists(gitea_api: pygitea, owner: string, repo: string) -> bool:
    repo_response: requests.Response = gitea_api.get('/repos/' + owner + '/' + repo)
    if repo_response.ok:
        print_warning(f'Project {repo} does already exist in Gitea, skipping!')

    return repo_response.ok


def label_exists(gitea_api: pygitea, owner: string, repo: string, labelname: string) -> bool:
    existing_labels = get_labels(gitea_api, owner, repo)
    existing_label = existing_labels.get(labelname)

    if existing_label:
        print_warning(f'Label {labelname} already exists in project {owner}/{repo}, skipping!')

    return existing_label is not None


def milestone_exists(gitea_api: pygitea, owner: string, repo: string, title: string) -> bool:
    existing_milestones = get_milestones(gitea_api, owner, repo)
    existing_milestone = existing_milestones.get(title)

    if existing_milestone:
        print_warning(f'Milestone {title} already exists in project {owner}/{repo} skipping!')

    return existing_milestone is not None


#
# Import helper functions
#

def _import_project_labels(gitea_api: pygitea, labels: list[gitlab.v4.objects.ProjectLabel],
                           owner: string, repo: string):
    for label in labels:
        if label_exists(gitea_api, owner, repo, label.name):
            continue
        import_response: requests.Response = gitea_api.post(f'/repos/{owner}/{repo}/labels', json={
            'name': label.name,
            'color': label.color,
            'description': label.description  # currently not supported
        })
        if not import_response.ok:
            print_error('Label ' + label.name + ' import failed: ' + import_response.text)


def _import_project_milestones(gitea_api: pygitea, milestones: list[gitlab.v4.objects.ProjectMilestone], owner: string,
                               repo: string):
    for milestone in milestones:
        if milestone_exists(gitea_api, owner, repo, milestone.title):
            continue
        due_date = None
        if milestone.due_date is not None and milestone.due_date != '':
            due_date = dateutil.parser.parse(milestone.due_date).strftime('%Y-%m-%dT%H:%M:%SZ')

        import_response: requests.Response = gitea_api.post(f'/repos/{owner}/{repo}/milestones', json={
            'description': milestone.description,
            'due_on': due_date,
            'title': milestone.title,
        })
        if not import_response.ok:
            print_error(f'Milestone {milestone.title} import failed: {import_response.text}')
            continue
        existing_milestone = import_response.json()

        if existing_milestone:
            # update milestone state, this cannot be done in the initial import :(
            # TODO: gitea api ignores the closed state...
            update_response: requests.Response = gitea_api.patch(
                f'/repos/{owner}/{repo}/milestones/{existing_milestone["id"]}',
                json={
                    'description': milestone.description,
                    'due_on': due_date,
                    'title': milestone.title,
                    'state': milestone.state
                })
            if not update_response.ok:
                print_error(f'Milestone {milestone.title} update failed: {update_response.text}')


def _import_issue_comments(gitea_api: pygitea, owner: str, repo: str, iid: int, db_notes: dict[int, dict],
                           notes: list[gitlab.v4.objects.ProjectIssueNote]):
    for note in notes:
        import_response: requests.Response = gitea_api.post(
            f'/repos/{owner}/{repo}/issues/{iid}/comments',
            json={
                'body': note.body
            }
        )
        if not import_response.ok:
            print_error(f'Comment of issue {owner}/{repo} #{iid} import failed: {import_response.text}')
            continue

        imported = import_response.json()

        # import created/updated time
        db_note = db_notes[note.id]
        try:
            c.gt_cur.execute(
                '''
                update comment set
                created_unix = %s, updated_unix = %s, poster_id = %s
                where id = %s
                ''', (
                    db_note['created_at'].timestamp(),
                    db_note['updated_at'].timestamp(),
                    user_id_map[note.author['id']],
                    imported['id']
                ))
        except:
            print_error(traceback.format_exc())
    c.gt_cn.commit()


def _import_project_issues(gitea_api: pygitea, issues: list[gitlab.v4.objects.ProjectIssue],
                           owner: string, repo: string, db_issues: dict[int, dict], db_notes: dict[int, dict]):
    # reload all existing milestones and labels, needed for assignment in issues
    # milestones = get_milestones(gitea_api, owner, repo)
    labels = get_labels(gitea_api, owner, repo)

    for issue in sorted(issues, key=lambda x: x.iid):
        due_date = ''
        if issue.due_date is not None:
            due_date = dateutil.parser.parse(issue.due_date).strftime('%Y-%m-%dT%H:%M:%SZ')

        assignee = None
        if issue.assignee is not None:
            assignee = issue.assignee['username']

        assignees = []
        for tmp_assignee in issue.assignees:
            assignees.append(tmp_assignee['username'])

        # milestone = None
        # if issue.milestone is not None:
        #     if milestone := milestones.get(issue.milestone['title']):
        #         milestone = milestone['id']

        new_labels = []
        for label in issue.labels:
            label = labels.get(label)
            if label:
                new_labels.append(label['id'])

        import_response: requests.Response = gitea_api.post(f'/repos/{owner}/{repo}/issues', json={
            'assignee': assignee,
            'assignees': assignees,
            'body': issue.description,
            'closed': issue.state == 'closed',
            'due_on': due_date,
            'labels': new_labels,
            # 'milestone': milestone,
            'title': issue.title,
        })
        if not import_response.ok:
            print_error(f'Issue {issue.title} import failed: {import_response.text}')
            continue

        imported = import_response.json()

        # import comments
        _import_issue_comments(gitea_api, owner, repo, imported['number'], db_notes, issue.notes.list(all=True))

        # import created/updated time
        db_issue = db_issues[issue.id]
        try:
            c.gt_cur.execute(
                '''
                update issue set
                created_unix = %s, updated_unix = %s, closed_unix = %s, poster_id = %s
                where id = %s
                ''',
                (
                    db_issue['created_at'].timestamp(),
                    db_issue['updated_at'].timestamp(),
                    db_issue['closed_at'].timestamp() if db_issue['closed_at'] else None,
                    user_id_map[issue.author['id']],
                    imported['id']
                )
            )
        except:
            print_error(traceback.format_exc())
    c.gt_cn.commit()


def _import_project_repo(gitea_api: pygitea, namespace_path: str, project: gitlab.v4.objects.Project):
    project_path = name_clean(project.path)

    if repo_exists(gitea_api, namespace_path, project_path):
        return

    clone_url = project.http_url_to_repo
    if GITLAB_ADMIN_PASS == '' and GITLAB_ADMIN_USER == '':
        clone_url = project.ssh_url_to_repo
    private = project.visibility == 'private' or project.visibility == 'internal'

    namespace = get_namespace(gitea_api, namespace_path)
    if not namespace:
        print_error(f'Failed to load namespace {namespace_path}')
        return

    description = project.description

    if description is not None and len(description) > 255:
        description = description[:255]
        print_warning(f'Description of {namespace_path}/{project_path} had to be truncated to 255 characters!')

    import_response: requests.Response = gitea_api.post('/repos/migrate', json={
        'auth_password': GITLAB_ADMIN_PASS,
        'auth_username': GITLAB_ADMIN_USER,
        'clone_addr': clone_url,
        'description': description,
        'mirror': False,
        'private': private,
        'repo_name': project_path,
        'uid': namespace['id']
    })
    if not import_response.ok:
        print_error(f'Project {namespace_path}/{project_path} import failed: {import_response.text}')
        return
    imported = import_response.json()

    project_id_map[project.id] = imported['id']


def _import_project_repo_collaborators(gitea_api: pygitea, namespace_path: str,
                                       collaborators: list[gitlab.v4.objects.ProjectMember],
                                       project: gitlab.v4.objects.Project):
    project_path = name_clean(project.path)
    for collaborator in collaborators:

        if collaborator_exists(gitea_api, namespace_path, project_path, collaborator.username):
            continue
        permission = 'read'

        if collaborator.access_level == 10:  # guest access
            permission = 'read'
        elif collaborator.access_level == 20:  # reporter access
            permission = 'read'
        elif collaborator.access_level == 30:  # developer access
            permission = 'write'
        elif collaborator.access_level == 40:  # maintainer access
            permission = 'admin'
        elif collaborator.access_level == 50:  # owner access (only for groups)
            print_error('Group members are currently not supported!')
            continue  # groups are not supported
        else:
            print_warning(f'Unsupported access level {collaborator.access_level}, setting permissions to "read"!')

        import_response: requests.Response = gitea_api.put(
            f'/repos/{namespace_path}/{project_path}/collaborators/{collaborator.username}',
            json={
                'permission': permission
            }
        )
        if not import_response.ok:
            print_error(f'Collaborator {collaborator.username} import failed: {import_response.text}')


def _import_users(gitea_api: pygitea, users: list[gitlab.v4.objects.User], notify: bool = False):
    print_info('Importing users')
    c.gl_cur.execute('''select * from users''')
    db_users = {x['id']: x for x in c.gl_cur.fetchall()}
    for user in tqdm(users):
        keys: list[gitlab.v4.objects.UserKey] = user.keys.list(all=True)

        if user.username in ('alert-bot', 'support-bot', 'ghost'):
            continue

        if not (imported := user_exists(gitea_api, user.username)):
            tmp_password = 'Tmp1!' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
            tmp_email = user.username + '@noemail-git.local'  # Some gitlab instances do not publish user emails
            try:
                tmp_email = user.email
            except AttributeError:
                print_warning(f'Email of user {user.username} is unknown')
                pass
            import_response: requests.Response = gitea_api.post('/admin/users', json={
                'email': tmp_email,
                'full_name': user.name,
                'login_name': user.username,
                'password': tmp_password,
                'send_notify': notify,
                'source_id': 0,  # local user
                'username': user.username
            })
            if not import_response.ok:
                print_error(f'User {user.username} import failed: {import_response.text}')
                continue
            imported = import_response.json()

        user_id_map[user.id] = imported['id']
        db_user = db_users[user.id]

        # import created/updated/last_login time
        try:
            c.gt_cur.execute(
                '''
                update "user" set
                created_unix = %s, updated_unix = %s, last_login_unix = %s
                where id = %s
                ''', (
                    db_user['created_at'].timestamp(),
                    db_user['updated_at'].timestamp(),
                    db_user['current_sign_in_at'].timestamp() if db_user['current_sign_in_at'] else None,
                    imported['id']
                ))
        except:
            print_error(traceback.format_exc())
        c.gt_cn.commit()

        # import public keys
        _import_user_keys(gitea_api, keys, user)


def _import_user_keys(gitea_api: pygitea, keys: list[gitlab.v4.objects.UserKey], user: gitlab.v4.objects.User):
    for key in keys:
        if user_key_exists(gitea_api, user.username, key.title):
            print_error(f'Public key {key.title} of user {user.username} already exists')
            continue

        import_response: requests.Response = gitea_api.post(f'/admin/users/{user.username}/keys', json={
            'key': key.key,
            'read_only': True,
            'title': key.title,
        })
        if not import_response.ok:
            print_error(f'Public key {key.title} import failed: {import_response.text}')
            continue

        imported = import_response.json()

        # import created/updated time
        try:
            c.gt_cur.execute(
                '''
                update public_key set
                created_unix = %s, updated_unix = %s
                where id = %s
                ''', (
                    to_tz_timestamp(key.created_at),
                    to_tz_timestamp(key.created_at),
                    imported['id']
                ))
        except:
            print_error(traceback.format_exc())
    c.gt_cn.commit()


def get_full_namespace_path(db_groups: dict[int, dict], namespace_id: int):
    current_group = db_groups[namespace_id]
    full_path = current_group['path']
    while parent_id := current_group['parent_id']:
        current_group = db_groups[parent_id]
        full_path = current_group['path'] + '_' + full_path
    return name_clean(full_path)


def _import_groups(gitea_api: pygitea, groups: list[gitlab.v4.objects.Group]):
    print_info('Importing groups')
    c.gl_cur.execute('''select * from namespaces''')
    db_groups = {x['id']: x for x in c.gl_cur.fetchall()}

    for group in tqdm(groups):
        members: list[gitlab.v4.objects.GroupMember] = group.members.list(all=True)

        if organization_exists(gitea_api, name_clean(group.path)):
            print_error('Group ' + name_clean(group.path) + ' already exists')
            continue

        db_group = db_groups[group.id]
        full_path = get_full_namespace_path(db_groups, group.id)

        import_response: requests.Response = gitea_api.post('/orgs', json={
            'description': group.description,
            'full_name': group.full_name,
            'username': full_path
        })
        if not import_response.ok:
            print_error(f'Group {full_path} import failed: {import_response.text}')
            continue

        imported = import_response.json()
        group_id_map[group.id] = imported['id']

        # import created/updated time
        try:
            c.gt_cur.execute(
                '''
                update "user" set
                created_unix = %s, updated_unix = %s
                where id = %s
                ''', (
                    db_group['created_at'].timestamp(),
                    db_group['updated_at'].timestamp(),
                    imported['id']
                ))
        except:
            print_error(traceback.format_exc())
        c.gt_cn.commit()

        # import group members
        _import_group_members(gitea_api, full_path, members)


def _import_group_members(gitea_api: pygitea, full_path: str, members: list[gitlab.v4.objects.GroupMember]):
    # TODO: create teams based on gitlab permissions (access_level of group member)
    existing_teams = get_teams(gitea_api, full_path)
    if not existing_teams:
        print_error(f'Failed to import members to group {full_path}: no teams found!')
        return
    first_team = existing_teams[0]

    # add members to teams
    for member in members:
        if member_exists(gitea_api, member.username, first_team['id']):
            continue
        import_response: requests.Response = gitea_api.put(f'/teams/{first_team["id"]}/members/{member.username}')
        if not import_response.ok:
            print_error(f'Failed to add member {member.username} to group {full_path}! {import_response.text}')


#
# Import functions
#

def import_users_groups(gitlab_api: gitlab.Gitlab, gitea_api: pygitea, notify=False):
    # read all users
    users: list[gitlab.v4.objects.User] = gitlab_api.users.list(all=True)
    groups: list[gitlab.v4.objects.Group] = gitlab_api.groups.list(all=True)

    # print('Found ' + str(len(users)) + ' gitlab users as user ' + gitlab_api.user.username)
    # print('Found ' + str(len(groups)) + ' gitlab groups as user ' + gitlab_api.user.username)

    # import all non existing users
    _import_users(gitea_api, users, notify)

    # import all non existing groups
    _import_groups(gitea_api, groups)


def import_projects(gitlab_api: gitlab.Gitlab, gitea_api: pygitea):
    print_info('Importing projects')
    # read all projects and their issues
    projects: list[gitlab.v4.objects.Project] = gitlab_api.projects.list(all=True)

    c.gl_cur.execute('''select * from issues''')
    db_issues = {x['id']: x for x in c.gl_cur.fetchall()}
    c.gl_cur.execute('''select * from notes where noteable_type = 'Issue' ''')
    db_notes = {x['id']: x for x in c.gl_cur.fetchall()}

    for project in tqdm(projects):
        try:
            collaborators: list[gitlab.v4.objects.ProjectMember] = project.members.list(all=True)
            labels: list[gitlab.v4.objects.ProjectLabel] = project.labels.list(all=True)
            # milestones: list[gitlab.v4.objects.ProjectMilestone] = project.milestones.list(all=True)
            issues: list[gitlab.v4.objects.ProjectIssue] = project.issues.list(all=True)
        except Exception as e:
            print_error(f'Importing project {project.path} failed\n{traceback.format_exc()}')
            continue

        c.gl_cur.execute('''select * from namespaces''')
        db_groups = {x['id']: x for x in c.gl_cur.fetchall()}
        namespace_path = get_full_namespace_path(db_groups, project.namespace['id'])
        project_name = name_clean(project.path)

        # import project repo
        _import_project_repo(gitea_api, namespace_path, project)

        # import collaborators
        _import_project_repo_collaborators(gitea_api, namespace_path, collaborators, project)

        # import labels
        _import_project_labels(gitea_api, labels, namespace_path, project_name)

        # import milestones
        # _import_project_milestones(gitea_api, milestones, namespace_path, project_name)

        # import issues
        _import_project_issues(gitea_api, issues, namespace_path, project_name, db_issues, db_notes)


def import_events():
    print_info('Importing events')

    c.gl_cur.execute('''select * from events''')
    db_events = c.gl_cur.fetchall()
    c.gl_cur.execute('''select * from projects''')
    db_projects = {x['id']: x for x in c.gl_cur.fetchall()}
    c.gl_cur.execute('''select * from push_event_payloads''')
    push_events = {x['event_id']: x for x in c.gl_cur.fetchall()}

    for event in tqdm(db_events):
        if event['action'] != 5:
            continue
        db_project = db_projects[event['project_id']]
        push_event = push_events[event['id']]

        try:
            c.gt_cur.execute(
                '''
                insert into action
                (user_id, op_type, act_user_id, repo_id, comment_id, ref_name, is_private, created_unix)
                values (%s, %s, %s, %s, %s, %s, %s, %s)
                ''', (
                    user_id_map[event['author_id']],
                    5,  # commit
                    user_id_map[event['author_id']],
                    project_id_map[event['project_id']],
                    0,
                    'refs/heads/' + push_event['ref'],
                    db_project['visibility_level'] <= 10,
                    event['created_at'].timestamp()
                ))
        except:
            print_error(traceback.format_exc())
    c.gt_cn.commit()


#
# Helper functions
#

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def color_message(color, message, colorend=bcolors.ENDC, bold=False):
    if bold:
        return bcolors.BOLD + color_message(color, message, colorend, False)

    return color + message + colorend


def print_color(color, message, colorend=bcolors.ENDC, bold=False):
    print(color_message(color, message, colorend))


def print_info(message):
    print_color(bcolors.OKBLUE, message)


def print_success(message):
    print_color(bcolors.OKGREEN, message)


def print_warning(message):
    print_color(bcolors.WARNING, message)


def print_error(message):
    global GLOBAL_ERROR_COUNT
    GLOBAL_ERROR_COUNT += 1
    print_color(bcolors.FAIL, message)


def name_clean(name):
    newName = name.replace(' ', '_')
    newName = re.sub(r'[^a-zA-Z0-9_\.-]', '-', newName)

    if (newName.lower() == 'plugins'):
        return newName + '-user'

    return newName


if __name__ == '__main__':
    main()
