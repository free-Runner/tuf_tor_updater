Introduction
=================================
1. repository_operator.py
---------------------------------
Before using repository_operator.py, you should first install tuf-repository-tool.

```python
  # see help log
  $ python repository_operator.py --help
  # generate a new repo metadata and client, with -nd means 'no delegation'
  $ python repository_operator.py --generate_repository [-nd] dir_name
  # generate a new temp dir with dir_name, with -nd means 'no delegation'
  $ python repository_operator.py --generate_file_dir [-nd] dir_name
  # update a repo metadata with new generated targets files, with -nd means 'no delegation'
  $ python repository_operator.py --update_repository [-nd] dir_name
```

2. writemetainfo.py
---------------------------------
Use writemetainfo.py to generate the metainfo of speicific file(s) in writemetainfo_dir directory.
Without metainfo file, you cannot download an update with softwareupdater.py

```python
  $ python writemetainfo.py private_key_file_name public_key_file_name
```


3. scripts
---------------------------------
when using this script, you should first modify this script so that it is your os directory's path.
you should have your tuf platform and repy v1 platform so that you could run your code.

```python
  # run the script
  # generate new repo
  $ . ./create_repository.sh
  # update repo
  $ . ./update_repository.sh
  # test to download with softwareupdater.py
  $ . ./safe_download.sh
```
