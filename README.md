# vault_whisperer
Hashicorp Vault Whisperer (python lib)

## Its just a scratch.

### Installation:
pip3 install git+https://github.com/papko26/vault_whisperer

### Usage example:
```bash
export VAULT_TOKEN=token-value-here
python3
```
```python
>>> import vault_whisperer
>>> my_vault = vault_whisperer.vault("/path/to/config.conf")
>>> action_status = my_vault.check_copy_secret_dir("services/service1/user1/", "services/service2/user1/", no_struct=True)
>>> print (action_status)
True
```

More usage examples can be found in the end of src file vault_whisperer.py

Example of config file can be found in tests/whisperer.conf

Default client have no options to make reliable, transaction-like calls. And have no options for recursive lists/delete/move of asserts. So, this lib can. One day I will document it properly, I hope so.

