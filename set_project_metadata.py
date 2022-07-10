from tqdm import tqdm

from utils import Conn, get_full_namespace_path, name_clean

if __name__ == '__main__':
    c = Conn()
    c.gl_cur.execute('''select * from projects''')
    projects = {x['id']: x for x in c.gl_cur.fetchall()}
    c.gl_cur.execute('''select * from namespaces''')
    groups = {x['id']: x for x in c.gl_cur.fetchall()}
    c.gl_cur.execute('''select * from fork_network_members''')
    forks = {x['project_id']: x for x in c.gl_cur.fetchall()}

    c.gt_cur.execute('''select * from repository''')
    repos = {(x['owner_name'], x['name']): x for x in c.gt_cur.fetchall()}

    for project in tqdm(projects.values()):
        namespace_path = get_full_namespace_path(groups, project['namespace_id'])
        project_name = name_clean(project['path'])
        add = ''
        add_p = ()
        if (proj_id := project['id']) in forks and (f_proj_id := forks[proj_id]['forked_from_project_id']):
            add = ', is_fork = true, fork_id = %s'
            forked = projects[f_proj_id]
            f_namespace_path = get_full_namespace_path(groups, forked['namespace_id'])
            f_project_name = name_clean(forked['path'])
            add_p = (repos[f_namespace_path, f_project_name]['id'],)

        c.gt_cur.execute(f'''
            update repository set created_unix = %s, updated_unix = %s{add}
            where owner_name = %s and name = %s
        ''', (
            project['created_at'].timestamp(), project['last_activity_at'].timestamp(), *add_p,
            namespace_path, project_name
        ))
    c.gt_cn.commit()

