#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018-2020, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

import base64
import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

# <cert>
#     <refid>5c8517362ff41</refid>
#     <descr>webConfigurator default (5c8517362ff41)</descr>
#     <type>server</type>
#     <crt>LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVlakNDQTJLZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREJhTVRnd05nWURWUVFLRXk5d1psTmwKYm5ObElIZGxZa052Ym1acFozVnlZWFJ2Y2lCVFpXeG1MVk5wWjI1bFpDQkRaWEowYVdacFkyRjBaVEVlTUJ3RwpBMVVFQXhNVmNHWlRaVzV6WlMwMVl6ZzFNVGN6TmpKbVpqUXhNQjRYRFRFNU1ETXhNREV6TlRVd01sb1hEVEkwCk1EZ3pNREV6TlRVd01sb3dXakU0TURZR0ExVUVDaE12Y0daVFpXNXpaU0IzWldKRGIyNW1hV2QxY21GMGIzSWcKVTJWc1ppMVRhV2R1WldRZ1EyVnlkR2xtYVdOaGRHVXhIakFjQmdOVkJBTVRGWEJtVTJWdWMyVXROV000TlRFMwpNell5Wm1ZME1UQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQUxEbUNuY1J6N1RJCmlCcytBL0ZqMis5TVdzWmZHNHlTRzlWVS9ISHE5MTlhdUsyd2E4UkhyMld3KzdhcnU1YXVuV3pCMkZ0aERvcjkKMm1hYWIzaUVCRERqK2loMGY3N3E0cGo4TVZEM3E2SXdsWnd3NjBMdGpqdXBJTExHZGIrSlZGR20wc0hYY25HTQplemF3YWlhckptK0VTblQ1WUpyQ3QySitGTzBoNndoeW0zWGM5Zy9COTQyZEhrcEVJR053MVQ4bGg2TnhIeHhPCmZmczYxWExXTkdoQTllV3dnWWhVQWc0bXlGMUhQU1poa21Ic1JROXRsUHppeGJqZmY3NzZaTmgwVWFxUVlqa3YKWFE4RWxvSEx1N2FreHJJMEVtK3BtZjNrMS9lN3JEUnpnRDN0anQwc1NQSFVFTkZkaC9aMkVUQTlyTTZzeXhRNApKV20zVVlXdUlSTUNBd0VBQWFPQ0FVa3dnZ0ZGTUFrR0ExVWRFd1FDTUFBd0VRWUpZSVpJQVliNFFnRUJCQVFECkFnWkFNQXNHQTFVZER3UUVBd0lGb0RBekJnbGdoa2dCaHZoQ0FRMEVKaFlrVDNCbGJsTlRUQ0JIWlc1bGNtRjAKWldRZ1UyVnlkbVZ5SUVObGNuUnBabWxqWVhSbE1CMEdBMVVkRGdRV0JCUXg1VEg1cFpiZGlBajBHdmpmb1R1MApzTitUVHpDQmdnWURWUjBqQkhzd2VZQVVNZVV4K2FXVzNZZ0k5QnI0MzZFN3RMRGZrMCtoWHFSY01Gb3hPREEyCkJnTlZCQW9UTDNCbVUyVnVjMlVnZDJWaVEyOXVabWxuZFhKaGRHOXlJRk5sYkdZdFUybG5ibVZrSUVObGNuUnAKWm1sallYUmxNUjR3SEFZRFZRUURFeFZ3WmxObGJuTmxMVFZqT0RVeE56TTJNbVptTkRHQ0FRQXdIUVlEVlIwbApCQll3RkFZSUt3WUJCUVVIQXdFR0NDc0dBUVVGQ0FJQ01DQUdBMVVkRVFRWk1CZUNGWEJtVTJWdWMyVXROV000Ck5URTNNell5Wm1ZME1UQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFobm53VW9TdGJOa2FNM3c1ZUNIaE9ZOTkKb1ZpVUpnSTB4N1lNQ05XYWNpSkxucnA3S2ttd1FTdWdkdHRsTUxaWVhZclM5UXNpUytIY09SMUdlaFJSZ2srMwp5ZXBOV0E5ZDg5NE52TndDejZaY0gvOUZjTXk4eUZiQWpMNFZjaUJhR3VpUnozbGZJT1RGNUxwdGMvbGhSQXRDCmxhZml1U05NVG5sV2RudTRLUXlUbS9ZcnZTVjViRklWaFhhQmhLek1MMzV6U0d2Ukh5QUtYTHNYbTR6d3JBVDAKZXdVRm1BODNqRS9odk1HSzRRUHhZWG1KK28vWE9lRGw0NTVEQ1VMU2JUaWlBK3dCdGV6enExNzd2akN6Um5uWQpVNk1vNndVVWFqSlB4YUZLS1hNa0JVOHpYZ0ZZN1RZby80NGNUWUhBUW5hYUJJWWdlQ2FQQVFmWnJpT3JWZz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K</crt>
#     <prv>LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRQ3c1Z3AzRWMrMHlJZ2IKUGdQeFk5dnZURnJHWHh1TWtodlZWUHh4NnZkZldyaXRzR3ZFUjY5bHNQdTJxN3VXcnAxc3dkaGJZUTZLL2RwbQptbTk0aEFRdzQvb29kSCsrNnVLWS9ERlE5NnVpTUpXY01PdEM3WTQ3cVNDeXhuVy9pVlJScHRMQjEzSnhqSHMyCnNHb21xeVp2aEVwMCtXQ2F3cmRpZmhUdEllc0ljcHQxM1BZUHdmZU5uUjVLUkNCamNOVS9KWWVqY1I4Y1RuMzcKT3RWeTFqUm9RUFhsc0lHSVZBSU9Kc2hkUnowbVlaSmg3RVVQYlpUODRzVzQzMysrK21UWWRGR3FrR0k1TDEwUApCSmFCeTd1MnBNYXlOQkp2cVpuOTVOZjN1NncwYzRBOTdZN2RMRWp4MUJEUlhZZjJkaEV3UGF6T3JNc1VPQ1ZwCnQxR0ZyaUVUQWdNQkFBRUNnZ0VCQUt0aG96L3FWS1hjSmVqbXN5RTVVc25LMnFNWFgzUlgxWGxnQmRkRUFmY3kKeUhzVjBjSnVoT0pyamVKVERNR1dXRlFXbFVzcWc5RnEwUjNZZnlodUZqVmJtVzk2Tm8wN3VON29iY3I0dUNMQgpHU0VpVDdzZXRVN2RzeDBnb3RFMjlpYkpEYVRZMnpwaEZMcE9QZmxLbFVrekRJTzVXcnQwN0FBVEVLa1ExRWp3ClMyM1E1NEZEaE9kbW9GcXpzNE5tTzNSeC9oelpFRk00ckQ3NzR4MXprOTkwTmp6bHVVNnI3S2o1QVc1a1NsNEoKN0hkb2Z2VEpMNEtZSHdoVHYwbXZDWU5xcUVobnVDZ0xzcW9rTC8xN09UaEEyOVkwVUVMcWZNMUNra0JsemkySQpuS2l0eWFudDBlWHhLMjRROWxaMW9xdld3ZncrTEhTUzNCTlhQbjZmUXhrQ2dZRUEyanFBZHNMRXkxS0F6T05MCmI2eFp5YVBnUHRURzNLbXhmQVdnZk1CRzhZckU1WGFaVlhoTUhxRkFMZWkvQTNOaXZiTDFrMnZySmJmUVdDbnoKcmxTMnRQR0hCMXVjRjRWcGMrazJnT0tpQW0vbGJkMnp4THJnQ0p6VFlIcHZTSGprZ3VOblBLS1A5bFRZaTN6Ywp4NlBiOUlDTXpBMnlNVUxCT2VoWWtpczRxblVDZ1lFQXo0US8yRkkvR3o2aDVLT3AvVzgrOHpYbTNiOXdrL0s5CmhmdU5zN0JnSTNyODdpZHBMRU03UXhSZWFTdlRSTkp1YWFkOUU3YnJML0wyaDBlL0IxeFlSd2FDSjU0S2I5NmYKQVBEWW1GN3U3Vm5adURTVDQ0cE54OGQxTmZ1TjZoTld1aWovb2dLVnVpWiszek42MFpMWjRHMVJ4Zk1SS3prZAp5NW1NWWJNeDNHY0NnWUFXY0p1VEdyWUh2a1VXVEcwT1g2ZWY3MlQ0c1FKOTRFa3EycDFGRnJSMDAvTXBNVWZWCkhSaWVzYkFheUdzVDNNS1RoUnB4ZlZCaHdZUC8vTmhjM2NNbjJnb3JmSVVSZWh0ODJzZEsrNEx6UXpSUlZ0SE0KY2ZibGk5TEVnZko5ZmtqcEdKOGVBZzFScENuY05ndXh6NnluZUt5QnN3cld1K21JbmRhMXVSSUxuUUtCZ0ZrdAp1Rkk2Wml4TEtqK2JwZjNueE9HNEZGTFBabzN1RDB4NDRsaUtQNFovNEJwb2pXWWNMbWVSWlZGRktERzNUUVBTCm1vblNYaGZwRGREdElFY0ZoRnBoamFXQTRYTlo5SEx2RGVYTlJsaHgrSUtVOWNrZk1uWGNYWjZwVUQ5N3VCV2cKY05zcXlUV0tQWk9tQiszd2NmbGtnWFBVRlZqQjN2QVVPS1B6NGtXWkFvR0JBSkt1QlBaNE13T0pWc0VRVklUTApRbEd1UEZRTGtORnlqZWVYc2htdGVzeVRycXFuSGp2am1wVE5kOS9TMkZvWTU3eGEwOHVrVXRwZDlOM0NXWUxyClFRaXp5QmFPQXZveGhESFd0TFVDTEZBcUtEbmRSNjhuNmVoZzQxdmlBaktHM1VyakJLMjl4V0g2UDRTMzh4Mm0KVmJFZnl3YXgrYUd5bGEwY2lzNkdYVDBFCi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K</prv>
# </cert>

CERT_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),

    descr=dict(required=True, type='str'),
    type=dict(default='server', type='str'),
    crt=dict(required=True, type='str'),
    prv=dict(required=True, type='str'),
    ca_descr=dict(default=None, type='str')
)

class PFSenseCertModule(PFSenseModuleBase):
    """ module managing pfsense certificertte authorities """

    def __init__(self, module, pfsense=None):
        super(PFSenseCertModule, self).__init__(module, pfsense)
        self.name = "pfsense_cert"
        self.root_elt = self.pfsense.root
        self.certs = self.pfsense.get_elements('cert')

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return CERT_ARGUMENT_SPEC

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        if params['state'] == 'present':
            cert = params['crt']
            lines = cert.splitlines()
            if not(lines[0] == '-----BEGIN CERTIFICATE-----' and lines[-1] == '-----END CERTIFICATE-----'):
                self.module.fail_json(msg='Could not recognize cert format: %s' % (cert))
            prv = params['prv']
            lines = prv.splitlines()
            if not(lines[0] == '-----BEGIN PRIVATE KEY-----' and lines[-1] == '-----END PRIVATE KEY-----'):
                self.module.fail_json(msg='Could not recognize private key format: %s' % (prv))
            
            if self.params["ca_descr"] and not self.pfsense.find_ca_elt(self.params["ca_descr"]):
                self.module.fail_json(msg=f'Could not find CA with descr, {self.params["ca_descr"]}')


    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()
        self.obj = obj

        if params['state'] == 'present':
            self._get_ansible_param(obj, 'descr')
            self._get_ansible_param(obj, 'type')
            obj["crt"] = base64.b64encode(bytes(params['crt'],'utf-8')).decode()
            obj["prv"] = base64.b64encode(bytes(params['prv'],'utf-8')).decode()
            if self.params["ca_descr"]:
                obj["caref"] = self.pfsense.find_ca_elt(self.params["ca_descr"]).find("refid").text

        return obj

    ##############################
    # XML processing
    #
    def _find_target(self):
        result = self.root_elt.findall("cert[descr='{0}']".format(self.obj['descr']))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple certificertte authorities for name {0}.'.format(self.obj['descr']))
        else:
            return None

    def _find_this_cert_index(self):
        return self.certs.index(self.target_elt)

    def _find_last_cert_index(self):
        if len(self.certs):
            return list(self.root_elt).index(self.certs[len(self.certs) - 1])
        else:
            return len(list(self.root_elt))

    def _create_target(self):
        """ create the XML target_elt """
        self.obj['refid'] = self.pfsense.uniqid()
        return self.pfsense.new_element('cert')

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return self.obj['descr']

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        return values

    ##############################
    # run
    #
    def _update(self):
        return self.pfsense.phpshell('')



def main():
    module = AnsibleModule(
        argument_spec=CERT_ARGUMENT_SPEC,
        required_if=[],
        supports_check_mode=True)

    pfmodule = PFSenseCertModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
