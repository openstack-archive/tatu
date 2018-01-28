# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_log import log as logging

from tatu.config import KEYSTONE as ks

LOG = logging.getLogger(__name__)

def getProjectRoleNames(proj_id):
    role_ids = set()
    for r in ks.role_assignments.list(project=proj_id):
        role_ids.add(r.role['id'])
    return getRoleNamesForIDs(list(role_ids))

def getProjectRoleNamesForUser(proj_id, user_id):
    role_ids = []
    for r in ks.role_assignments.list(user=user_id, project=proj_id,
                                      effective=True):
        role_ids.append(r.role['id'])
    return getRoleNamesForIDs(role_ids)

def getRoleNamesForIDs(ids):
    names = []
    for id in ids:
        #TODO(pino): use a cache?
        names.append(ks.roles.get(id).name)
    return names

def getUserNameForID(id):
    return ks.users.get(id).name

def getProjectNameForID(id):
    return ks.projects.get(id).name

def getUserIdsByGroupId(id):
    return [u.id for u in ks.users.list(group=id)]
