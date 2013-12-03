Introduction
=================================
1. repository_operator.py
---------------------------------
Before using repository_operator.py, you should first install tuf-repository-tool.
* See the help log.

```python

  $ python repository_operator.py --help
  *** Hello ...
  --Help info--
  Usage: 
  """
  before generate new repository directory, you should make sure that there
  is a basic legal temp directory to put your update files, you could create by
  yourself, or use "generate_file_dir" to generate a directory and just put your
  files into the directory.
  1. Generate TUF repository, syntax:
  $python repository_operator.py --generate_repository directory_name
  2. Genrerate new TUF repository for update, syntax:
  $python repository_operator.py --update_repository directory_name
  3. Generate TUF repository without delegations, syntax:
  $python repository_operator.py --generate_repository -nd directory_name
  4. Generate new TUF repository for update without delegations, syntax:
  $python repository_operator.py --update_repository -nd directory_name
  5. Update and refresh the timestamp role's expire date, syntax:
  $python repository_operator.py --refresh_timestamp
  6. Update and refresh the release role's expire date, syntax:
  $python repository_operator.py --refresh_release
  7. Update and refresh the targets role's expire date, syntax:
  $python repository_operator.py --refresh_targets
  8. Update and refresh the root role's expire date, syntax:
  $python repository_operator.py --refresh_root
  """

```

* Generate a completely new repo metadata and client, with -nd means 'no delegation'

```python

  # generate a new repo metadata and client, here with '-nd' as an example
  $ python repository_operator.py --generate_repository -nd targets_files
  *** Hello ...
  Input Server path:
  # Here input the server path on your computer
  /home/laiwang/Documents/apache_Server/
  Server path:  /home/laiwang/Documents/apache_Server/
  Input client path:
  # Here input the client path, actually client is in different environment from server
  # Here just use local client as an example, but in different path
  /home/laiwang/Documents/repy_tuf/client/
  Client path: /home/laiwang/Documents/repy_tuf/client/
  # After input the server and client path, we also need to input the path of writemetainfo_dir
  # And we also need to input the path of private key and public key which are used to
  # generate the metainfo of softwareupdater.py
  *** Hello ...
  Create directory  targets_files
  Warning: 'tor-browser-2.3.25-14_en-US.exe' not in previous metainfo file!
  Writing a metafile with updates to:
  >>> Updating targets_files files ...
  >>> Creating RSA keys ...
  >>> Creating root, timestamp, release and targets ...
  >>> Copying target files ...
  >>> Adding target files ...
  >>> Making client directory ...
  *** Process complete ...
  >>> Updating /home/laiwang/Documents/apache_Server/ files ...
  >>> Updating /home/laiwang/Documents/repy_tuf/client/ files ...
  
```

* Update repository and the server metadata

```python
  # Here we also use "-nd" as an example
  $ python repository_operator.py --update_repository -nd targets_files
  *** Hello ...
  Input Server path:
  # Here we also need to input our server path
  /home/laiwang/Documents/repy_tuf/client/
  Server path:  /home/laiwang/Documents/repy_tuf/client/
  # Here we also need to input the path of writemetainfo_dir
  # And to input the path of private key and public key which are used to generate the
  # metainfo of softwareupdater.py, but we do not need to input the client path
  # since we just need to update the server and the client will handle that
  *** Hello ...
  Create directory  targets_files
  Warning: 'tor-browser-2.3.25-14_en-US.exe' not in previous metainfo file!
  Writing a metafile with updates to:
  >>> Updating targets_files files ...
  *** Hello ...
  >>> updating target files ...
  >>> Copying target files ...
  >>> Adding target files ...
  >>> Making client directory ...
  >>> Updating /home/laiwang/Documents/repy_tuf/client/ files ...
  
```
* It is the same op when generate repository with delegation.
* And for safe reason, the timestamp will expire only in one day, so before it expires, we should refresh the expire date by adding one day.

```python

  # Here just using --refresh_timestamp command
  $ python repository_operator.py --refresh_timestamp
  Input Server path:
  # Here also we should input the server path.
  Server path:  /home/laiwang/Documents/apache_Server/
  >>> Updating /home/laiwang/Documents/apache_Server/ files ...

```

* Now we have successfully update the expire date.
* The same operation for the release, targets and root roles.

2. writemetainfo.py
---------------------------------
Use writemetainfo.py to generate the metainfo of speicific file(s) in writemetainfo_dir directory.
Without metainfo file, you cannot download an update with softwareupdater.py
Since the writemetainfo.py has been merged into the repository_operator.py, so we do not need to run this alone.

```python

  # python writemetainfo.py private_key_file_name public_key_file_name
  $ python writemetainfo.py lw1378.privatekey lw1378.publickey
  Warning: 'tor-browser-2.3.25-14_en-US.exe' not in previous metainfo file!
  Writing a metafile with updates to:
  
```

3. scripts
---------------------------------
Before using scripts, the input path should be modified in scripts. 

```python
  # run the script
  # generate new repo
  $ . ./create_repository.sh
  # update repo
  $ . ./update_repository.sh
  # test to download with softwareupdater.py
  $ . ./safe_download.sh
```
