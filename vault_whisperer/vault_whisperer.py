import requests
import os
import sys
import logging
import json
from configparser import ConfigParser

lgr = logging.getLogger(__name__)

class vault():

    def __init__(self,
                config_file,
                vault_token_name="VAULT_TOKEN",
                config_main_section="whisperer",
                config_api_addr_option="api_addr",
                config_kv_value_option="kv_name"):

        parser = ConfigParser()

        self.separator = "=================================================================================================================================="

        if not vault_token_name in os.environ:
            lgr.critical("No {} in env".format(vault_token_name))
            sys.exit()
        if not os.path.exists(config_file):
            lgr.critical("No config file found in path {}".format(config_file))
            sys.exit()

        parser.read(config_file)

        if not parser.has_option(config_main_section, config_api_addr_option):
            lgr.critical("Config file had no mandatory option: {}".format(config_api_addr_option))
            sys.exit()

        if not parser.has_option(config_main_section, config_kv_value_option):
            lgr.critical("Config file had no mandatory option: {}".format(config_kv_value_option))
            sys.exit()
        
        self.vault_api_addr = parser[config_main_section][config_api_addr_option]
        self.vault_kv_name = parser[config_main_section][config_kv_value_option] 
        self.vault_api_token_header = {'X-Vault-Token': os.environ[vault_token_name]}
        
    def _secret_path_validator(self,path):
        """
            Internal function that validates given string to be valid for furher functions usage
        """
        if type(path) is str:
            if path[0] == "/":
                return path[1:]
            else:
                return path
        else:
            lgr.warning("Incorrect path")
            return False

    def _secret_payload_checker(self, payload):
        """
            Internal function that validates given payload to be valid for furher functions usage
            >: any arg
            <: returns given arg if its a dict, formating it to {"data":{arg}}, if not aledy
            <F: returns false if given arg is not a dic
        """
        if type(payload) is dict:
            if "data" in payload and len(payload) == 1:
                return payload
            else:
                return dict({"data":payload})
        else:
            lgr.warning("Wrong type of payload")
            return False
            



    def is_secret_exists(self, secret_path, verbose=True):
        """
            Checks if secret is exist by given path

        """
        checked_secret_path = self._secret_path_validator(secret_path)
        if not checked_secret_path:
            return False
        else:
            secret_path = checked_secret_path

        check_string = "{}{}/metadata/{}".format(self.vault_api_addr, self.vault_kv_name,secret_path)
        try:
            api_reply = requests.get(check_string, headers=self.vault_api_token_header)
        except Exception as e:
            lgr.critical("Some network or connection issues {}".format(e.args))
            return False

        if api_reply.status_code == 200:
            return True
        else:
            if verbose:
                lgr.info("Secret does not exists")
            return False


    def check_delete_secret(self, secret_path):
        """
            Deletes secret by given path
        """
        checked_secret_path = self._secret_path_validator(secret_path)
        if not checked_secret_path:
            return False
        else:
            secret_path = checked_secret_path

        if self.is_secret_exists(secret_path):
            destroy_string = "{}{}/metadata/{}".format(self.vault_api_addr, self.vault_kv_name,secret_path)
            try:
                api_reply = requests.delete(destroy_string, headers=self.vault_api_token_header)
            except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
            if api_reply.status_code == 204:
                if not self.is_secret_exists(secret_path, False):
                    return True
                else:
                    lgr.error("Command accepted, but secret not deleted (yet?) 0_o: {}".format(api_reply.content))
            else:
                lgr.error("Unexpected error when deleting: {}".format(api_reply.content))
                return False
        else:
            lgr.error("No such secret")
            return False
    

    def _create_or_update_secret(self, secret_path, payload):
        """
        Internal function for creating or updating secret by given path and payload.
        It also checks if given args are correct, and everything is goes like it should be.
        >: secret path as string
        >: payload as dict{"data":{"key":"value"}, {"key":"value"}}
        <T: returns true if action done
        <F: returns false if not, or some error occured 
        """
        checked_secret_path = self._secret_path_validator(secret_path)
        if not checked_secret_path:
            return False
        else:
            secret_path = checked_secret_path

        checked_payload = self._secret_payload_checker(payload)
        if not checked_payload:
            return False
        else:
            payload = checked_payload

        create_string ="{}{}/data/{}".format(self.vault_api_addr, self.vault_kv_name,secret_path)
        try:
            api_reply = requests.post(create_string, headers=self.vault_api_token_header, data=json.dumps(payload))
        except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False

        if api_reply.status_code == 200:
            return True
        else:
            lgr.error("Updating/Deleting of secret failed for some reason: {}".format(api_reply.content))
            return False

    def check_create_or_update_secret(self, secret_path, payload, force=False):
        """
        This one is only for creating/modifying (based on force flag) secret by given path and payload.
        It also checks if secret is really created, and was not created alredy.
        """

        if not self.is_secret_exists(secret_path):
            if self._create_or_update_secret(secret_path, payload):
                if self.is_secret_exists(secret_path):
                    return True
                else:
                    lgr.error("Command accepted, but secret not created (yet?) 0_o")
                    return False
            else:
                lgr.error("Unexpected error, when creating secret")
                return False
        else:
            if not force:
                lgr.error("Secret alredy exists. Use force=True to modify it.")
                return False
            else:
                if self._create_or_update_secret(secret_path, payload):
                    if self.is_secret_exists(secret_path):
                        return True
                    else:
                        lgr.error("Command accepted, but secret not created (yet?) 0_o")
                        return False
                else:
                    lgr.error("Unexpected error, when creating secret")
                    return False


            
    def read_secret_data(self, secret_path):
        """
        This on reads secret by given path, and returns its data
        """

        checked_secret_path = self._secret_path_validator(secret_path)
        if not checked_secret_path:
            return False
        else:
            secret_path = checked_secret_path

        if self.is_secret_exists(secret_path):
            read_string = "{}{}/data/{}".format(self.vault_api_addr, self.vault_kv_name,secret_path)
            try:
                api_reply = requests.get(read_string, headers=self.vault_api_token_header)
            except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
            if api_reply.status_code == 200:
                data=json.loads(api_reply.content.decode('utf-8'))
                return dict({"data":data['data']['data']})
            else:
                lgr.error("Unexpected error from vault")
                lgr.error(api_reply.status_code)
                lgr.error(api_reply.content)
                return False
        else:
            lgr.error("No such secret")
            return False



    def check_move_secret(self, old_path, new_path, force=False):
        """
        This one moves secret (modifying dst secret if force flag set)
        """

        checked_secret_path = self._secret_path_validator(old_path)
        if not checked_secret_path:
            return False
        else:
            old_path = checked_secret_path

        checked_secret_path = self._secret_path_validator(new_path)
        if not checked_secret_path:
            return False
        else:
            new_path = checked_secret_path

        if self.is_secret_exists(old_path):
            old_data = self.read_secret_data(old_path)
            if self.is_secret_exists(new_path):
                if not force:
                    lgr.error("Destination secret alredy exists! Use force=True to force me rewrite it.")
                    return False
                else:
                    if self.check_create_or_update_secret(new_path, old_data, force):
                        if self.check_delete_secret(old_path):
                            return True
                        else:
                            lgr.error("Destination updated, but source cant be deleted")
                            return False
                    else:
                        lgr.error("Cant update new secret")
                        return False

            else:
                if self.check_create_or_update_secret(new_path, old_data):
                    if self.is_secret_exists(new_path):
                        if self.check_delete_secret(old_path):
                            return True
                        else:
                            lgr.error("Destination created, but source cant be deleted")
                            return False
                    else:
                        lgr.error("Comand accepted, but secret not created 0_o")
                        return False
                else:
                    lgr.error("Cant create new secret")
                    return False
        else:
            lgr.error("No source secret to move")
            return False


    def check_copy_secret(self, old_path, new_path, force=False):
        """
        This one copies secret from one path to another 
        """

        checked_secret_path = self._secret_path_validator(old_path)
        if not checked_secret_path:
            return False
        else:
            old_path = checked_secret_path

        checked_secret_path = self._secret_path_validator(new_path)
        if not checked_secret_path:
            return False
        else:
            new_path = checked_secret_path

        if self.is_secret_exists(old_path):
            old_data = self.read_secret_data(old_path)
            if self.is_secret_exists(new_path):
                if not force:
                    lgr.error("Destination secret alredy exists! Use force=True to force me rewrite it.")
                    return False
                else:
                    if self.check_create_or_update_secret(new_path, old_data, force):
                        return True
                    else:
                        return False
            else:
                if self.check_create_or_update_secret(new_path, old_data):
                    if self.is_secret_exists(new_path):
                        return True
                    else:
                        lgr.error("Comand accepted, but secret not created 0_o")
                        return False
                else:
                    lgr.error("Cant create new secret")
                    return False
        else:
            lgr.error("No source secret to move")
            return False


    def _secret_path_dir_fixer(self, path):
        """
        internal function to check and fix if path given without slash
        """
        if not path.endswith('/'):
            return (path + "/")
        else:
            return (path)

    def _path_without_level(self, base, path):
        """
        internal function to retrive path part without indent level for recursive copy
        """
        levels_in_path = len(base.split("/"))
        return '/'.join(path.split("/")[-levels_in_path:])

    def _secret_name_by_path(self,path):
        """
        internal function to get only secret name without path
        """
        return path.split("/")[-1]

    def check_copy_secret_dir(self, src_path, dst_path, no_struct=False, force=False):
        """
        This one copies secrets directory recursively. 
        If flag no_struct passed = copies only secrets, without dirs structure
        If flag force passwd = rewrite secrets with duplicate names
        """
        src_path = self._secret_path_dir_fixer(src_path)
        dst_path = self._secret_path_dir_fixer(dst_path)
        status = -1
        secrets = self.list_directory(src_path)
        if secrets:
            status = len(secrets)
            for secret in secrets:
                secret_name = self._secret_name_by_path(secret)
                if no_struct:
                    new_target_secret_path = dst_path+secret_name
                else:
                    new_target_secret_path = dst_path+self._path_without_level(dst_path,secret)
                if self.check_copy_secret(secret, new_target_secret_path, force):
                    status -=1
        else:
            lgr.error("No secrets by given path")
            return False

        if not status:
            return True
        else:
            lgr.error("Something went worng (failed tasks count:{})".format(status))
            return False


    def check_move_secret_dir(self, src_path, dst_path, no_struct=False, force=False):
        """
        This one moves secrets directory recursively. 
        If flag no_struct passed = moves only secrets, without dirs structure
        If flag force passwd = rewrite secrets with duplicate names
        """
        src_path = self._secret_path_dir_fixer(src_path)
        dst_path = self._secret_path_dir_fixer(dst_path)
        status = -1
        secrets = self.list_directory(src_path)
        if secrets:
            status = len(secrets)
            for secret in secrets:
                secret_name = self._secret_name_by_path(secret)
                if no_struct:
                    new_target_secret_path = dst_path+secret_name
                else:
                    new_target_secret_path = dst_path+self._path_without_level(dst_path,secret)
                if self.check_copy_secret(secret, new_target_secret_path, force):
                    status -=1
            if not status:
                if self.check_delete_secret_dir(src_path):
                    return True
                else:
                    lgr.error("DST secrets created, but SRC cant be deleted")
                    return False
            else:
                lgr.error("Something went worng (failed tasks count:{})".format(status))
                return False
        else:
            lgr.error("No secrets by given path")
            return False

    def check_delete_secret_dir(self, secret_dir_path):
        """
        This one deletes secrets directory recursively. 
        """
        secret_dir_path = self._secret_path_dir_fixer(secret_dir_path)
        secrets = self.list_directory(secret_dir_path)
        status = -1
        if secrets:
            status = len(secrets)
            for secret in secrets:
                if self.check_delete_secret(secret):
                    status -= 1
            if not status:
                return True
            else:
                return False
        else:
            lgr.error("No secrets by given path")
            return False

        

    def list_directory(self, secret_dir_path, with_data=False, depth=1000, silent_error=False):
        """
        This one lists every secret and for directory
        If flag with_data passed - it also prints every secret data
        """
        secret_dir_path = self._secret_path_dir_fixer(secret_dir_path)

        custom_request = 'LIST'
        list_string = "{}{}/metadata/{}".format(self.vault_api_addr, self.vault_kv_name,secret_dir_path)
        reply = []
        try:
            api_reply = requests.request(custom_request, list_string, headers=self.vault_api_token_header)
        except Exception as e:
            lgr.critical("Some network or connection issues {}".format(e.args))
            return False
        if api_reply.status_code == 200:
            data = json.loads(api_reply.content.decode('utf-8'))
            keys = data['data']['keys']
            for key in keys:
                if depth>=0:
                    if key[-1:] == "/" and depth > 1:
                        reply = reply + self.list_directory(secret_dir_path+key, with_data, depth)
                    else:
                        if with_data:
                            reply.append({secret_dir_path+key : self.read_secret_data(secret_dir_path+key)})
                        else:
                            reply.append(secret_dir_path+key)
                    depth=depth-1
            return reply
        else:
            if not silent_error:
                lgr.error("No such path!")
            return False


    def human_readable_list_directory(self,secret_dir_path, with_data, depth):
        """
        This one lists every secret for directory in human readable format
        """        
        data = self.list_directory(secret_dir_path, with_data, depth)
        for item in data:
            print (item)
            print ()

    def _acl_name_validator(self, acl_name):
        """
        Internal function that validates given string to be valid for furher functions usage
        """
        if type(acl_name) is str:
            return acl_name
        else:
            lgr.warning("Incorrect acl_name")
            return False
        

    def is_policy_exists(self, acl_name, verbose=True):
        """
        Takes acl_name as arg, and check if it exists
        """

        checked_acl= self._acl_name_validator(acl_name)
        if not checked_acl:
            return False
        else:
            acl_name = checked_acl

        list_string = "{}sys/policies/acl/{}".format(self.vault_api_addr,acl_name)
        try:
            api_reply = requests.get(list_string, headers=self.vault_api_token_header)
        except Exception as e:
            lgr.critical("Some network or connection issues {}".format(e.args))
            return False
        if api_reply.status_code == 200:
            return True
        else:
            if verbose:
                lgr.info("Secret does not exists")
            return False

    def read_policy_data(self, acl_name):
        """
        Takes acl_name as arg, and returns it data
        """
        checked_acl= self._acl_name_validator(acl_name)
        if not checked_acl:
            return False
        else:
            acl_name = checked_acl

        if self.is_policy_exists(acl_name):
            get_string = "{}sys/policies/acl/{}".format(self.vault_api_addr,acl_name)
            try:
                api_reply = requests.get(get_string, headers=self.vault_api_token_header)
            except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
            if api_reply.status_code == 200:
                data=json.loads(api_reply.content.decode('utf-8'))
                return dict(data['data'])
            else:
                lgr.error("Policy exists, but I cant get it 0_o")
                return False
        else:
            lgr.error("No such policy")
            return False

    def _create_or_update_policy(self, acl_name, payload):
        """
        Internal, that creates any policy by given name and payload
        payload example:
        {'name': 'test1','policy': 'path "GI/data/services/test1/*" {\n    capabilities = ["create", "read", "list"]\n}'}))
        """
        create_string = "{}sys/policies/acl/{}".format(self.vault_api_addr,acl_name)
        try:
            api_reply = requests.put(create_string, headers=self.vault_api_token_header, data=json.dumps(payload))
        except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
        if api_reply.status_code == 204:
            return True
        else:
            lgr.error("Unexpected error when creating policy")
            return False

    def check_create_or_update_policy(self, acl_name, payload, force=False):
        """
        This one creates policy and check if it created
        """
        if force or not self.is_policy_exists(acl_name):
            self._create_or_update_policy(acl_name, payload)
            if self.is_policy_exists(acl_name):
                return True
            else:
                lgr.error("Command set, but not created 0_o (yet?)")
                return False
        else:
            lgr.error("Policy exists, but force flag not set. Wont replace it")
            return False

    def check_delete_policy(self, acl_name):
        """
        This one deletes policy
        """
        if self.is_policy_exists(acl_name):
            delete_string = "{}sys/policies/acl/{}".format(self.vault_api_addr,acl_name)
            try:
                api_reply = requests.delete(delete_string, headers=self.vault_api_token_header)
            except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
            if api_reply.status_code == 204:
                if not self.is_policy_exists(acl_name, False):
                    return True
                else:
                    lgr.error("Policy was not deleted for some reasons")
                    return False
            else:
                lgr.error("Unexpected error when deleting policy")
                return False
        else:
            lgr.error("Policy does not exists!")
            return False

    def check_copy_policy(self, old_acl, new_acl, force=False, rename_inside=True):
        """
        Use it to copy policy.
        force - to replace any dst policy with same name
        rename_inside - to rename "name" inside acl data
        """
        if self.is_policy_exists(old_acl):
            data = self.read_policy_data(old_acl)
            if data:
                if rename_inside:
                    if "name" in data:
                        data.update({"name":new_acl})
                    else:
                        lgr.error("No name inside policy, this is minor fail, I will continue")
                        
                if self.check_create_or_update_policy(new_acl,data, force):
                    return True
                else:
                    lgr.error("Cant create dst policy")
                    return False
            else:
                lgr.error("Cant read src policy for some reason")
                return False

    def check_rename_policy(self, old_acl, new_name, force=False, rename_inside=True):
        """
        Use it to rename policy.
        force - to replace any dst policy with same name
        rename_inside - to rename "name" inside acl data
        """
        if self.is_policy_exists(old_acl):
            data = self.read_policy_data(old_acl)
            if data:
                if rename_inside:
                    if "name" in data:
                        data.update({"name":new_name})
                    else:
                        lgr.error("No name inside policy, this is minor fail, I will continue")

                if self.check_create_or_update_policy(new_name,data, force):
                    if self.check_delete_policy(old_acl):
                        return True
                    else:
                        lgr.error("Cant delete src policy")
                        return False
                else:
                    lgr.error("Cant create dst policy")
                    return False
            else:
                lgr.error("Cant read src policy for some reason")
                return False


    def list_policies(self):
        list_string = "{}sys/policy".format(self.vault_api_addr)
        try:
            api_reply = requests.get(list_string, headers=self.vault_api_token_header)
        except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
        reply = []
        if api_reply.status_code == 200:
                data=json.loads(api_reply.content.decode('utf-8'))
                all_policies = data['policies']
                for policy in all_policies:
                    reply.append(self.read_policy_data(policy))
                return reply
        else:
                lgr.error("Unexpected reply from vault")
                return False

    def human_readable_list_policies(self, with_data=False):
        data = self.list_policies(with_data)
        for item in data:
            print (item)
            print (self.separator)

    def is_approle_exists(self, approle_name):
        """
        Just check if approle with such name alredy exists T/F
        """
        get_string = "{}auth/approle/role/{}".format(self.vault_api_addr,approle_name)
        try:
            api_reply = requests.get(get_string, headers=self.vault_api_token_header)
        except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
        if api_reply.status_code == 200:
            return True
        else:
            return False

    def read_approle_data(self, approle_name):
        """
        Get approle by it name (will return dict {approle_name:data})
        """
        if self.is_approle_exists(approle_name):
            get_string = "{}auth/approle/role/{}".format(self.vault_api_addr,approle_name)
            try:
                api_reply = requests.get(get_string, headers=self.vault_api_token_header)
            except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
            if api_reply.status_code == 200:
                    data=json.loads(api_reply.content.decode('utf-8'))
                    return data['data']
            else:
                lgr.error("Approle exists, but cant read it 0_o")
                return False
        else:
            lgr.error("Approle does not exists!")
            return False
    def role_create_payload_generator(self, policies_array, secret_id_ttl, token_num_uses, token_ttl, token_max_ttl, bind_secret_id=True, secret_id_bound_cidrs=[],token_bound_cidrs=[],secret_id_num_uses =0,period="",enable_local_secret_ids=False):
        """
        Smal duty function to not go mad while trying to remember all approle options
        """
        data = {"policies":policies_array, "secret_id_ttl":secret_id_ttl, "token_num_uses":token_num_uses, "token_ttl":token_ttl, "token_max_ttl":token_max_ttl, "secret_id_bound_cidrs":secret_id_bound_cidrs, "token_bound_cidrs":token_bound_cidrs, "secret_id_num_uses":secret_id_num_uses, "period":period, "enable_local_secret_ids":enable_local_secret_ids}
        return data

    
    def _create_or_update_approle(self, approle_name, approle_data):
        """
        Internal for creating or updating approle by given data
        """
        create_string = "{}auth/approle/role/{}".format(self.vault_api_addr,approle_name)
        try:
                api_reply = requests.post(create_string, headers=self.vault_api_token_header, data=json.dumps(approle_data))
        except Exception as e:
            lgr.critical("Some network or connection issues {}".format(e.args))
            return False
        if api_reply.status_code == 204:
            return True
        else:
            lgr.error("Cant create approle")
            return False

    def check_create_or_update_approle(self, approle_name, approle_data, check_policies=True, force=False):
        """
        Creates or updates approle by given name and upload
        change check_policies flag for check or not is requested policies alredy exists
        change force flag, for create approle even if it alredy exist
        """
        if check_policies and "policies" in approle_data:
            for policy in approle_data['policies']:
                if not self.is_policy_exists(policy):
                    lgr.error("Create policy for {} first".format(policy))
                    return False
        
        if force or not self.is_approle_exists(approle_name):
            if self._create_or_update_approle(approle_name, approle_data):
                if self.is_approle_exists(approle_name):
                    return True
                else:
                    lgr.error("Command accepted, but approle not created 0_o (yet?)")
                    return False
            else:
                lgr.error("Approle exists, but force flag not set. Wont replace it")
                return False


    def list_approles(self, with_data=False):
        """
        List all existing approles, with contents, or not
        """
        custom_request = 'LIST'
        list_string = "{}auth/approle/role".format(self.vault_api_addr)
        try:
            api_reply = requests.request(custom_request,list_string, headers=self.vault_api_token_header)
        except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
        reply = []
        if api_reply.status_code == 200:
            data=json.loads(api_reply.content.decode('utf-8'))
            for key in data['data']['keys']:
                if with_data:
                    reply.append({key:{"data":self.read_approle_data(key)}})
                else:
                    reply.append(key)
            return reply
        else:
            lgr.error("Unexpected reply from vault")
            return False

    def human_readable_list_approles(self, with_data=False):
        for item in self.list_approles(with_data):
            print (item)
            print (self.separator)

    def check_delete_approle(self, approle_name):
        """
        Delete approle by its name
        """
        if self.is_approle_exists(approle_name):
            delete_string = "{}auth/approle/role/{}".format(self.vault_api_addr,approle_name)
            try:
                api_reply = requests.delete(delete_string, headers=self.vault_api_token_header)
            except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
            if api_reply.status_code == 204:
                if not self.is_approle_exists(approle_name):
                    return True
                else:
                    lgr.error("Request sent, but role not deleted (yet?) 0_o")
                    return False
        else:
            lgr.error("No such approle")
            return False

    def check_rename_approle(self, old_approle, new_approle, force=False, check_policies=True):
        """
        Rename approle. Set force flag to replace dst approle, if it alredy exists
        """
        if force or not self.is_approle_exists(new_approle):
            if self.is_approle_exists(old_approle):
                data = self.read_approle_data(old_approle)
                if data:
                    if self.check_create_or_update_approle(new_approle, data, force=force, check_policies=check_policies):
                        if self.check_delete_approle(old_approle):
                            return True
                        else:
                            lgr.error("New approle created, but old not deleted")
                            return False
                    else:
                        lgr.error("Cant create new approle")
                        return False
                else:
                    lgr.error("Cant read src approle")
                    return 
            else:
                lgr.error("Src approle dont exists")
                return False
        else:
            lgr.error("Approle with such name alredy exist, but force flag not set. Wont replace it")
            return False


    def token_to_accessor(self, token):
        """
        Pass token and get it's accessor
        """
        lookup_string = "{}auth/token/lookup".format(self.vault_api_addr)
        try:
            api_reply = requests.post(lookup_string, headers=self.vault_api_token_header, data=json.dumps({"token": token}))
        except Exception as e:
            lgr.critical("Some network or connection issues {}".format(e.args))
            return False
        if api_reply.status_code == 200:
            data = json.loads(api_reply.content.decode('utf-8'))
            return data['data']['accessor']
        else:
            lgr.error("Looks like token does not exists")
            return False

    def token_name_to_accessors(self, token_name, verbose=True):
        """
        Pass token_name and get all associated accesors
        """
        reply = []
        tkndl = self.list_tokens()
        for tknd in tkndl:
            data = self.check_read_token_data(tknd)
            if data['data']['display_name'] == token_name:
                reply.append(tknd)
        if not reply:
            if verbose:
                lgr.error("No tokens with such name")
            return False
        else:
            return reply

    def list_tokens(self, with_data=False):
        """
        List all existing tokens (and its data if with_data dlag is set)
        """
        custom_request = 'LIST'
        list_string = "{}auth/token/accessors".format(self.vault_api_addr)
        try:
            api_reply = requests.request(custom_request,list_string, headers=self.vault_api_token_header)
        except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
        reply = []
        if api_reply.status_code == 200:
            data=json.loads(api_reply.content.decode('utf-8'))
            for key in data['data']['keys']:
                if with_data:
                    reply.append(self.read_token_data(key))
                else:
                    reply.append(key)
            return reply
        else:
            lgr.error("Unexpected reply from vault")
            return False

    def is_token_exists(self, token_accessor, verbose=True):
        """
        Check if token exists, by its accessor
        """
        lookup_string = "{}auth/token/lookup-accessor".format(self.vault_api_addr)
        try:
            api_reply = requests.post(lookup_string, headers=self.vault_api_token_header, data=json.dumps({"accessor": token_accessor}))
        except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
        if api_reply.status_code == 200:
            return True
        else:
            if verbose:
                lgr.error("Token does not exist")
            return False

    def read_token_data(self, token_accessor):
        """
        Read token, by its accessor
        """
        if self.is_token_exists(token_accessor):
            lookup_string = "{}auth/token/lookup-accessor".format(self.vault_api_addr)
            try:
                api_reply = requests.post(lookup_string, headers=self.vault_api_token_header, data=json.dumps({"accessor": token_accessor}))
            except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
            if api_reply.status_code == 200:
                data = json.loads(api_reply.content.decode('utf-8'))
                return dict({"data":data['data']})
            else:
                lgr.error("Unexpected error")
                return False
        else:
            return False

    def token_payload_generator(self, display_name, num_uses, policies_array, ttl ,meta_map={}, no_parent = False, id="", role_name="", no_default_policy=False, renewable=True, explicit_max_ttl="", period=""):
        """
        Smal internal function to not go mad while trying to remember all token options
        """
        data = {"display_name":display_name, "num_uses":num_uses, "policies":policies_array, "ttl":ttl, "meta":meta_map, "no_parent":no_parent, "id":id, "role_name":role_name, "no_default_policy":no_default_policy, "renewable":renewable, "explicit_max_ttl":explicit_max_ttl, "period":period}
        return data
#untested===========================
    def create_token(self, payload):
        """
        Create token using payload (you may use token_payload_generator)
        PS: No point to check_delete implementation, only accessor and token are uniq
        """
        lookup_string = "{}auth/token/create".format(self.vault_api_addr)
        try:
            api_reply = requests.post(lookup_string, headers=self.vault_api_token_header, data=json.dumps(payload))
        except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
        if api_reply.status_code == 200:
            data = json.loads(api_reply.content.decode('utf-8'))
            return data['auth']['client_token']
        else:
            lgr.error("Unexpected error")
            return False


    def check_delete_token(self, token_accessor):
        """
        Delete token, and check if its really done
        """
        if self.is_token_exists(token_accessor):
            lookup_string = "{}auth/token/revoke-accessor".format(self.vault_api_addr)
            try:
                api_reply = requests.post(lookup_string, headers=self.vault_api_token_header, data=json.dumps({"accessor": token_accessor}))
            except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
            if api_reply.status_code == 204:
                if not self.is_token_exists(token_accessor, False):
                    return True
                else:
                    lgr.error("Request sent, but token not deleted (yet?) 0_o")
                    return False
            else:
                lgr.error("Unexpected error(may be token alredy deleted by ttl?)")
                return False
        else:
            lgr.error("Token does not exist")
            return False


    def human_readable_list_tokens(self, with_data=False):
        for item in self.list_tokens(with_data):
            print (item)
            print (self.separator)

"""
gi_vault = vault()

#SECRETS:
#Creating new secret:
print(gi_vault.check_create_or_update_secret("services/test1/test2/test3/secret3", {"secret3-key": "secret3-secret"}))
#Reading secret:
print(gi_vault.read_secret_data("services/test1/test2/test3/secret3"))
#Modifying secret:
print(gi_vault.check_create_or_update_secret("services/test1/test2/test3/secret3",{"secret3-key-modified": "secret3-secret-modified"}, force=True))
#Copy secret from one location to another: 
print(gi_vault.check_copy_secret("services/test1/test2/test3/secret3", "services/test1/test2/secret_from_3"))
#Copy secret from one location to another and force rewrite duplicates:
print(gi_vault.check_copy_secret("services/test1/test2/test3/secret3", "services/test1/test2/secret_from_3", force=True))
#Deleting secret:
print(gi_vault.check_delete_secret("services/test1/test2/secret_from_3"))
#Moving secret:
print(gi_vault.check_move_secret("services/test1/test2/test3/secret3", "services/test1/test2/secret_from_3"))
#Directory removal:
print(gi_vault.check_delete_secret_dir("services/test1/"))
#Move secret from one location to another and force rewrite duplicates
print(gi_vault.check_move_secret("services/test1/test2/test3/secret3rr", "services/test1/test2/secret_from_3", force=True))
#Recursively copy dir from one path to another without structure (only copy secrets):
print(gi_vault.check_copy_secret_dir("services/test1/test2/test3", "services/test1", no_struct=True))
#Recursively copy dir from one path to another without structure (only copy secrets), force rewrite dups:
print(gi_vault.check_move_secret_dir("services/test1/test2/", "services/test1", no_struct=True, force=True))
#Recursively copy dir from one path to another with structure, force rewrite dups:
print(gi_vault.check_move_secret_dir("services/test1/test2/", "services/anotherpath/from_test2", force=True))
#List directory secrets (without content):
print(gi_vault.list_directory("services/test1/"))
#List directory secrets (with content):
print(gi_vault.list_directory("services/test1/",with_data=True))
#Recursively copy dir from one path to another without structure (only copy secrets):
print(gi_vault.check_copy_secret_dir("services/test1/test2/","services/another-test/", no_struct=True))
#Recursively move dir from one path to another with structure:
print(gi_vault.check_move_secret_dir("services/test1/test2/","services/another-test/"))
#Recursively move dir from one path to another without structure (only copy secrets):
print(gi_vault.check_move_secret_dir("services/test1/test2/","services/another-test/", no_struct=True))

POLICIES:
#Create new policy:
print(gi_vault.check_create_or_update_policy("test1", {'name': 'test1','policy': 'path "GI/data/services/test1/*" {\n    capabilities = ["create", "read", "list"]\n}'}))
#Read policy:
print(gi_vault.read_policy_data("test1"))
#Force update existing policy
print(gi_vault.check_create_or_update_policy("test1", force=True,{'name': 'test1','policy': 'path "GI/data/services/test12/*" {\n    capabilities = ["create", "read", "list"]\n}'}))
#Copy policy:
print(gi_vault.check_copy_policy("test1", "test141"))
#Copy policy and rewrite existing one:
print(gi_vault.check_copy_policy("test1", "test141", force=True))
#Copy policy, rewrite existing one and DONT rename "name" inside acl data:
print(gi_vault.check_copy_policy("test1", "test141", force=True, rename_inside=False))
#Rename policy:
print(gi_vault.check_rename_policy("test1", "test141"))
#It got same flags as copy, btw...:
print(gi_vault.check_rename_policy("test1", "test141", force=True, rename_inside=False))


APPROLES:
#Read approle by name
print(gi_vault.read_approle_data("test"))
#Delete approle by name
print(gi_vault.check_delete_approle("test"))
#Generate payload for create approle
gi_vault.role_create_payload_generator(["testrole"], 0, 2, 10,20, True)
#Create approle by generated payload
print(gi_vault.check_create_or_update_approle("test_approle", approle_payload))
#Create approle by generated payload (without policy check)
print(gi_vault.check_create_or_update_approle("test_approle", approle_payload, check_policies=False))
#Rename  approle (dont check policy)
print(gi_vault.check_rename_approle("test_approle", "test_approle_renamed", check_policies=False))
"""

#TODO: add tokens to doc
#TODO: build me as a pip package, I am fucking lib!
#TODO: https://www.vaultproject.io/api/auth/token/index.html
#TODO: implement  Revoke Token and Orphan Children
#TODO:  understand and implement Token Roles


