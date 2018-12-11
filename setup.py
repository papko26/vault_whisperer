from setuptools import setup

setup(name='vault_whisperer',
      version='0.1',
      description='Hashicorp Vault client lib',
      url='https://github.com/papko26/vault_whisperer',
      author='Max Shu',
      author_email='papko@papko.org',
      license='Apache',
      packages=['vault_whisperer'],
      install_requires=["requests"],
      zip_safe=False)
