import os
import sys
import shutil
import tempfile
import time
from ast import literal_eval
from writemetainfo import create_metainfo_file
from tuf.libtuf import *
from tuf.formats import parse_time
from tuf.formats import format_time

TIMESTAMP_EXPIRATION = 86400
ROOT_EXPIRATION = 31556900
TARGETS_EXPIRATION = 7889230
RELEASE_EXPIRATION = 604800

class Make_repository:
  def __init__(self):
    self.repository_path = "path/to/repository"

  def init_state(self):
    # init the state, clear all path directory
    base_path = os.path.dirname(__file__)
    path_path = os.path.join(base_path, "path")
    if os.path.exists(path_path):
      shutil.rmtree(path_path)

  def create_rsa_keys(self):
    print '>>> Creating RSA keys ...'
    # Generate and write the first of two root keys for the TUF repository.
    # The following function creates an RSA key pair, where the private key is saved to
    # "path/to/root_key" and the public key to "path/to/root_key.pub".
    # Here we pre-set the password as "lw1378".
    generate_and_write_rsa_keypair("path/to/root_key", bits = 2048, password = "lw1378")
    generate_and_write_rsa_keypair("path/to/root_key2", password = "lw1378")

  def create_repository_metadata(self):
    print '>>> Creating root, timestamp, release and targets ...'
    # Import an existing public key and an private key.
    # And for private key, we also pre-set the password.
    public_root_key = import_rsa_publickey_from_file("path/to/root_key.pub")
    private_root_key = import_rsa_privatekey_from_file("path/to/root_key", "lw1378")
    public_root_key2 = import_rsa_publickey_from_file("path/to/root_key2.pub")
    private_root_key2 = import_rsa_privatekey_from_file("path/to/root_key2", "lw1378")

    repository = create_new_repository(self.repository_path)
    # Create root
    # Add a public key
    repository.root.add_key(public_root_key)
    repository.root.add_key(public_root_key2)
    # Set threshold to 2, so that the root metadata file is considered valid if it 
    # contains at least two valid signatures. 
    repository.root.threshold = 2
    # Load the signing keys of the root
    repository.root.load_signing_key(private_root_key)
    repository.root.load_signing_key(private_root_key2)

    # Write release, timestamp and targets.
    # Generate keys for the remaining top-level roles.
    generate_and_write_rsa_keypair("path/to/targets_key", password="lw1378")
    generate_and_write_rsa_keypair("path/to/release_key", password="lw1378")
    generate_and_write_rsa_keypair("path/to/timestamp_key", password="lw1378")
    # Add the public keys of the remaining top-level roles.
    repository.targets.add_key(import_rsa_publickey_from_file("path/to/targets_key.pub"))
    repository.release.add_key(import_rsa_publickey_from_file("path/to/release_key.pub"))
    repository.timestamp.add_key(import_rsa_publickey_from_file("path/to/timestamp_key.pub"))
    # Import the signing keys of the remaining top-level roles.
    private_targets_key = import_rsa_privatekey_from_file("path/to/targets_key", "lw1378")
    private_release_key = import_rsa_privatekey_from_file("path/to/release_key", "lw1378")
    private_timestamp_key = import_rsa_privatekey_from_file("path/to/timestamp_key", "lw1378")
    # Load the signing keys of the remaining roles
    repository.targets.load_signing_key(private_targets_key)
    repository.release.load_signing_key(private_release_key)
    repository.timestamp.load_signing_key(private_timestamp_key)
    # Set the expiration date of the timestamp role.
    #repository.timestamp.expiration = "2014-10-28 12:08:00"
    #repository.targets.compressions = ["gz"]
    #repository.release.compressions = ["gz"]

    # Write the repository
    try:
      repository.write()
    except tuf.Error, e:
      print 'Failed to achieve the goal as ', str(e)

  # Use to copy file
  def _copy_files(self, src_path, dst_path):
    if not os.path.exists(dst_path):
      os.makedirs(dst_path)

    fileList = os.listdir(src_path)

    for files in fileList:
      files_path = os.path.join(src_path, files)
      if os.path.isdir(files_path):
        sub_src_path = os.path.join(src_path, files)
        sub_dst_path = os.path.join(dst_path, files)
        self._copy_files(sub_src_path, sub_dst_path)
        continue
      shutil.copy2(files_path, dst_path)

  def _remove_files(self, delete_path):
    if not os.path.exists(delete_path):
      print 'directory does not exist!'
      sys.exit()

    fileList = os.listdir(delete_path)

    for files in fileList:
      files_path = os.path.join(delete_path, files)
      if os.path.isdir(files_path):
        if files == 'django':
          continue
        shutil.rmtree(files_path)
        continue
      os.remove(files_path)

  def create_targets_file(self, update_file_dir):
    print '>>> Copying target files ...'
    # Create targets directory by copy files in a specific directory
    # which is in current directory
    if not os.path.exists(update_file_dir):
      print "directory does not exist !"
      sys.exit(0)
    # update_file_dir should contain a specific directory
    base_path = os.path.dirname(__file__)
    src_path = os.path.join(base_path, update_file_dir)

    if not os.path.exists(src_path):
      print "direct_dir does not exist!"
      sys.exit(0)
    
    # Copy all files in targets directory, and create django directory.
    targets_path = os.path.join(self.repository_path, "targets")

    # Copy files
    self._copy_files(src_path, targets_path)

  def directory_operation_no_delegation(self):
    repository = load_repository(self.repository_path)
    self._add_targets_file(repository)

  def directory_operation(self):
    repository = load_repository(self.repository_path)
    self._add_targets_file(repository)
    self._delegation_operation(repository)

  def modify_directory_no_delegation(self):
    repository= load_repository(self.repository_path)
    self._add_targets_file(repository)

  def _add_targets_file(self, repository):
    print '>>> Adding target files ...'
    # Get file list in targets directory.
    list_of_targets = repository.get_filepaths_in_directory("path/to/repository/targets/", recursive_walk=False, followlinks=True)
    # Add the list of target paths to the metadata of the Targets role.
    repository.targets.add_targets(list_of_targets)
    # The private key of the updated targets metadata must be loaded before it can be signed and
    # written. Here the passwords are pre-set.
    private_targets_key =  import_rsa_privatekey_from_file("path/to/targets_key", "lw1378")
    repository.targets.load_signing_key(private_targets_key)
    private_root_key = import_rsa_privatekey_from_file("path/to/root_key", "lw1378")
    private_root_key2 = import_rsa_privatekey_from_file("path/to/root_key2", "lw1378")
    private_release_key = import_rsa_privatekey_from_file("path/to/release_key", "lw1378")
    private_timestamp_key = import_rsa_privatekey_from_file("path/to/timestamp_key", "lw1378")
    repository.root.load_signing_key(private_root_key)
    repository.root.load_signing_key(private_root_key2)
    repository.release.load_signing_key(private_release_key)
    repository.timestamp.load_signing_key(private_timestamp_key)

    # Write the repository
    try:
      repository.write()
    except tuf.Error, e:
      print 'Failed to achieve the goal as ', str(e)

  def load_timestamp(self):
    # By default, the timestamp will expire in one day, so we have to load the signature again
    repository = load_repository(self.repository_path)

    private_release_key = import_rsa_privatekey_from_file("path/to/release_key", "lw1378")
    repository.release.load_signing_key(private_release_key)
    private_timestamp_key = import_rsa_privatekey_from_file("path/to/timestamp_key", "lw1378")
    repository.timestamp.load_signing_key(private_timestamp_key)

    # Load current time stamp
    try:
      timestamp_File = open("path/to/repository/metadata.staged/timestamp.txt", "r")
      timestamp_dic = literal_eval(timestamp_File.read())
      expire_time = parse_time(timestamp_dic['signed']['expires'])
      repository.timestamp.expiration = str(format_time(expire_time + TIMESTAMP_EXPIRATION)).replace(" UTC", "")
      #print format_time(expire_time + TIMESTAMP_EXPIRATION)
    except Exception, e:
      print 'Failed to update the expire date since', str(e)

    try:
      repository.write()
    except tuf.Error, e:
      print 'Failed to achieve the goal as ', str(e)

  def load_release(self):
    # By default, the timestamp will expire in one day, so we have to load the signature again
    repository = load_repository(self.repository_path)

    private_root_key = import_rsa_privatekey_from_file("path/to/root_key", "lw1378")
    repository.root.load_signing_key(private_root_key)
    private_targets_key = import_rsa_privatekey_from_file("path/to/targets_key", "lw1378")
    repository.targets.load_signing_key(private_targets_key)
    private_timestamp_key = import_rsa_privatekey_from_file("path/to/timestamp_key", "lw1378")
    repository.timestamp.load_signing_key(private_timestamp_key)
    private_release_key = import_rsa_privatekey_from_file("path/to/release_key", "lw1378")
    repository.release.load_signing_key(private_release_key)

    # Load current time stamp
    try:
      release_File = open("path/to/repository/metadata.staged/release.txt", "r")
      release_dic = literal_eval(release_File.read())
      expire_time = parse_time(release_dic['signed']['expires'])
      repository.release.expiration = str(format_time(expire_time + RELEASE_EXPIRATION)).replace(" UTC", "")
      #print format_time(expire_time + TIMESTAMP_EXPIRATION)
    except Exception, e:
      print 'Failed to update the expire date since', str(e)

    try:
      repository.write()
    except tuf.Error, e:
      print 'Failed to achieve the goal as ', str(e)

  def load_targets(self):
    # By default, the timestamp will expire in one day, so we have to load the signature again
    repository = load_repository(self.repository_path)

    private_root_key = import_rsa_privatekey_from_file("path/to/root_key", "lw1378")
    repository.root.load_signing_key(private_root_key)
    private_targets_key = import_rsa_privatekey_from_file("path/to/targets_key", "lw1378")
    repository.targets.load_signing_key(private_targets_key)
    private_timestamp_key = import_rsa_privatekey_from_file("path/to/timestamp_key", "lw1378")
    repository.timestamp.load_signing_key(private_timestamp_key)
    private_release_key = import_rsa_privatekey_from_file("path/to/release_key", "lw1378")
    repository.release.load_signing_key(private_release_key)

    # Load current time stamp
    try:
      targets_File = open("path/to/repository/metadata.staged/targets.txt", "r")
      targets_dic = literal_eval(targets_File.read())
      expire_time = parse_time(targets_dic['signed']['expires'])
      repository.targets.expiration = str(format_time(expire_time + TARGETS_EXPIRATION)).replace(" UTC", "")
      #print format_time(expire_time + TIMESTAMP_EXPIRATION)
    except Exception, e:
      print 'Failed to update the expire date since', str(e)

    try:
      repository.write()
    except tuf.Error, e:
      print 'Failed to achieve the goal as ', str(e)

  def load_root(self):
    # By default, the timestamp will expire in one day, so we have to load the signature again
    repository = load_repository(self.repository_path)

    private_root_key = import_rsa_privatekey_from_file("path/to/root_key", "lw1378")
    repository.root.load_signing_key(private_root_key)
    private_root_key2 = import_rsa_privatekey_from_file("path/to/root_key2", "lw1378")
    repository.root.load_signing_key(private_root_key2)
    private_targets_key = import_rsa_privatekey_from_file("path/to/targets_key", "lw1378")
    repository.targets.load_signing_key(private_targets_key)
    private_timestamp_key = import_rsa_privatekey_from_file("path/to/timestamp_key", "lw1378")
    repository.timestamp.load_signing_key(private_timestamp_key)
    private_release_key = import_rsa_privatekey_from_file("path/to/release_key", "lw1378")
    repository.release.load_signing_key(private_release_key)

    # Load current time stamp
    try:
      root_File = open("path/to/repository/metadata.staged/root.txt", "r")
      root_dic = literal_eval(root_File.read())
      expire_time = parse_time(root_dic['signed']['expires'])
      repository.root.expiration = str(format_time(expire_time + ROOT_EXPIRATION)).replace(" UTC", "")
      #print format_time(expire_time + TIMESTAMP_EXPIRATION)
    except Exception, e:
      print 'Failed to update the expire date since', str(e)

    try:
      repository.write()
    except tuf.Error, e:
      print 'Failed to achieve the goal as ', str(e)

  def modify_targets_file(self, update_file_dir, flag):
    print '>>> updating target files ...'
    repository = load_repository(self.repository_path)
    # First remove all existing targets
    base_path = os.path.dirname(__file__)
    targets_path = os.path.join(base_path, "path/to/repository/targets")

    if not os.path.exists(targets_path):
      print 'Bad metadata directory!'
      sys.exit(0)

    repository.targets.clear_targets()
    private_targets_key =  import_rsa_privatekey_from_file("path/to/targets_key", "lw1378")
    repository.targets.load_signing_key(private_targets_key)
    private_root_key = import_rsa_privatekey_from_file("path/to/root_key", "lw1378")
    private_root_key2 = import_rsa_privatekey_from_file("path/to/root_key2", "lw1378")
    private_release_key = import_rsa_privatekey_from_file("path/to/release_key", "lw1378")
    private_timestamp_key = import_rsa_privatekey_from_file("path/to/timestamp_key", "lw1378")
    repository.root.load_signing_key(private_root_key)
    repository.root.load_signing_key(private_root_key2)
    repository.release.load_signing_key(private_release_key)
    repository.timestamp.load_signing_key(private_timestamp_key)

    self._remove_files(targets_path)

    if flag == True:
      django_path = os.path.join(targets_path, "django")
      if not os.path.exists(django_path):
        print 'Illegal delegation directory'
        sys.exit(0)
      repository.targets.unclaimed.django.clear_targets()
      private_unclaimed_key = import_rsa_privatekey_from_file("path/to/unclaimed_key", "lw1378")
      repository.targets.unclaimed.django.load_signing_key(private_unclaimed_key)
      self._remove_files(django_path)

    try:
      repository.write()
    except tuf.Error, e:
      print 'Failed to achieve the goal as', str(e)

    self.create_targets_file(update_file_dir)
    self._add_targets_file(repository)

    if flag == True:
      django_path = os.path.join(targets_path, "django")
      self._delegation_update(repository, django_path)



  def _delegation_operation(self, repository):
    print '>>> Delegations operations ...'
    generate_and_write_rsa_keypair("path/to/unclaimed_key", bits=2048, password="lw1378")
    public_unclaimed_key = import_rsa_publickey_from_file("path/to/unclaimed_key.pub")
    repository.targets.delegate("unclaimed", [public_unclaimed_key], [])
    private_unclaimed_key = import_rsa_privatekey_from_file("path/to/unclaimed_key", "lw1378")
    repository.targets.unclaimed.load_signing_key(private_unclaimed_key)
    repository.targets.unclaimed.version = 2
    repository.targets.unclaimed.delegate("django", [public_unclaimed_key], [], restricted_paths=["path/to/repository/targets/django/"])
    repository.targets.unclaimed.django.load_signing_key(private_unclaimed_key)
    list_of_targets = repository.get_filepaths_in_directory("path/to/repository/targets/django/", recursive_walk=False, followlinks=True)
    # Add the list of target paths to the metadata of the Targets role.
    repository.targets.unclaimed.django.add_targets(list_of_targets)
    #repository.targets.unclaimed.django.compressions = ["gz"]
    # Write the repository
    try:
      repository.write()
    except tuf.Error, e:
      print 'Failed to achieve the goal as ', str(e)

    #repository.targets.unclaimed.delegate("flask", [public_unclaimed_key], [])
    #repository.targets.unclaimed.revoke("flask")
    # Write the repository
    #try:
      #repository.write()
    #except tuf.Error, e:
      #print 'Failed to achieve the goal as ', str(e)

  def _delegation_update(self, repository, source_dir):
    print '>>> Update delegations ...'
    list_of_targets = repository.get_filepaths_in_directory("path/to/repository/targets/django/", recursive_walk=False, followlinks=True)
    repository.targets.unclaimed.django.add_targets(list_of_targets)
    private_unclaimed_key = import_rsa_privatekey_from_file("path/to/unclaimed_key", "lw1378")
    repository.targets.unclaimed.django.load_signing_key(private_unclaimed_key)

    try:
      repository.write()
    except tuf.Error, e:
      print 'Failed to achieve the goal as', str(e)

  
  def make_metadata_dir(self):
    # Create a metadata directory and copy all files into it
    metadata_staged_path = os.path.join(self.repository_path, "metadata.staged")
    metadata_path = os.path.join(self.repository_path, "metadata")

    if not os.path.exists(metadata_staged_path):
      print "illegal repository, try to build it again !"
      sys.exit(0)
    if not os.path.exists(metadata_path):
      os.makedirs(metadata_path)
    else:
      shutil.rmtree(metadata_path)
      os.makedirs(metadata_path)

    # Copy all files.
    self._copy_files(metadata_staged_path, metadata_path)

  def make_client_dir(self):
    #print '>>> Making client directory ...'
    # Create Client
    base_path = os.path.dirname(__file__)
    client_path = os.path.join(base_path, "path/to/client")
    if os.path.exists(client_path):
      shutil.rmtree(client_path)
    create_tuf_client_directory("path/to/repository/", "path/to/client/")

  def cp_update_files(self, src_path, dst_path):
    # This is used when trying to update a directory.
    # If a file has exist, then just replace it with a new version.
    # When updating fails, then just return the original directory.
    print '>>> Updating', dst_path, 'files ...'
    src_fileList = os.listdir(src_path)
    dst_fileList = os.listdir(dst_path)
    tempdir = tempfile.mkdtemp() + "/"

    try:
      # Replace the old files and dirs in dst_path
      for files in dst_fileList:
        files_path = os.path.join(dst_path, files)
        if files in src_fileList:
          if os.path.isdir(files_path):
            shutil.rmtree(files_path)
            continue
          os.remove(files_path)

      self._copy_files(src_path, dst_path)
      shutil.rmtree(tempdir)
    except Exception, e:
      # Failed to update the files and dirs
      print 'Failed to update the files and dirs,', str(e)
      dst_filesList = os.listdir(dst_path)
      for files in dst_fileList:
        files_path = os.path.join(dst_path, files)
        if os.path.isdir(files_path):
          shutil.rmtree(files_path)
          continue
        os.remove(files_path)
      self._copy_files(tempdir, dst_path)
      shutil.rmtree(tempdir)

def copy_files_nd(src_name, src_path, dst_path):
  # This is used when copying a specific file but not directory
  if not os.path.exists(dst_path):
    print 'Directory does not exist!'
    sys.exit(0)

  dst_fileList = os.listdir(dst_path)
  for files in dst_fileList:
    files_path = os.path.join(dst_path, files)
    if files == src_name:
      os.remove(files_path)

  shutil.copy2(src_path, dst_path)

def copy_files(src_path, dst_path):
  mr = Make_repository()
  mr.cp_update_files(src_path, dst_path)

def generate_metadata(basic_directory, flag):
  #print '*** Hello ...'
  if flag is True:
    mr = Make_repository()
    mr.init_state()
    mr.create_rsa_keys()
    mr.create_repository_metadata()
    mr.create_targets_file(basic_directory)
    mr.directory_operation()
    mr.make_metadata_dir()
    mr.make_client_dir()
  else:
    mr = Make_repository()
    mr.init_state()
    mr.create_rsa_keys()
    mr.create_repository_metadata()
    mr.create_targets_file(basic_directory)
    mr.directory_operation_no_delegation()
    mr.make_metadata_dir()
    mr.make_client_dir()
  print '*** Process complete ...'

def refresh_timestamp_expire_data():
  mr = Make_repository()
  mr.load_timestamp()
  mr.make_metadata_dir()
  mr.make_client_dir()
  rep_path = "path/to/repository/"

  # Input server path
  while True:
    server_path = raw_input('Input Server path:')
    if os.path.exists(server_path):
      print 'Server path: ', server_path
      break
    else:
      print 'Server path is either invalid or server path does not exist!'

  copy_files(rep_path, server_path)
  # Modify the server, remove the keys of root and targets roles
  try:
    server_fileList = os.listdir(server_path)
    for files in server_fileList:
      files_path = os.path.join(server_path, files)
      if files == 'metadata.staged':
        if os.path.isdir(files_path):
          shutil.rmtree(files_path)
          continue
        os.remove(files_path)
      if files == 'metadata' and os.path.isdir(files_path):
        role_path = os.path.join(server_path, "metadata")
        role_fileList = os.listdir(role_path)
        for roles in role_fileList:
          roles_path = os.path.join(role_path, roles)
          if roles == 'root.txt':
            os.remove(roles_path)
            continue
          if roles == 'targets.txt':
            os.remove(roles_path)
            continue
  except Exception, e:
    print 'Error,', str(e)
    sys.exit(0)

def refresh_release_expire_data():
  mr = Make_repository()
  mr.load_release()
  mr.make_metadata_dir()
  mr.make_client_dir()
  rep_path = "path/to/repository/"

  # Input server path
  while True:
    server_path = raw_input('Input Server path:')
    if os.path.exists(server_path):
      print 'Server path: ', server_path
      break
    else:
      print 'Server path is either invalid or server path does not exist!'

  copy_files(rep_path, server_path)
  # Modify the server, remove the keys of root and targets roles
  try:
    server_fileList = os.listdir(server_path)
    for files in server_fileList:
      files_path = os.path.join(server_path, files)
      if files == 'metadata.staged':
        if os.path.isdir(files_path):
          shutil.rmtree(files_path)
          continue
        os.remove(files_path)
      if files == 'metadata' and os.path.isdir(files_path):
        role_path = os.path.join(server_path, "metadata")
        role_fileList = os.listdir(role_path)
        for roles in role_fileList:
          roles_path = os.path.join(role_path, roles)
          if roles == 'root.txt':
            os.remove(roles_path)
            continue
          if roles == 'targets.txt':
            os.remove(roles_path)
            continue
  except Exception, e:
    print 'Error,', str(e)
    sys.exit(0)

def refresh_targets_expire_data():
  mr = Make_repository()
  mr.load_targets()
  mr.make_metadata_dir()
  mr.make_client_dir()
  rep_path = "path/to/repository/"

  # Input server path
  while True:
    server_path = raw_input('Input Server path:')
    if os.path.exists(server_path):
      print 'Server path: ', server_path
      break
    else:
      print 'Server path is either invalid or server path does not exist!'

  copy_files(rep_path, server_path)
  # Modify the server, remove the keys of root and targets roles
  try:
    server_fileList = os.listdir(server_path)
    for files in server_fileList:
      files_path = os.path.join(server_path, files)
      if files == 'metadata.staged':
        if os.path.isdir(files_path):
          shutil.rmtree(files_path)
          continue
        os.remove(files_path)
      if files == 'metadata' and os.path.isdir(files_path):
        role_path = os.path.join(server_path, "metadata")
        role_fileList = os.listdir(role_path)
        for roles in role_fileList:
          roles_path = os.path.join(role_path, roles)
          if roles == 'root.txt':
            os.remove(roles_path)
            continue
          if roles == 'targets.txt':
            os.remove(roles_path)
            continue
  except Exception, e:
    print 'Error,', str(e)
    sys.exit(0)

def refresh_root_expire_data():
  mr = Make_repository()
  mr.load_root()
  mr.make_metadata_dir()
  mr.make_client_dir()
  rep_path = "path/to/repository/"

  # Input server path
  while True:
    server_path = raw_input('Input Server path:')
    if os.path.exists(server_path):
      print 'Server path: ', server_path
      break
    else:
      print 'Server path is either invalid or server path does not exist!'

  copy_files(rep_path, server_path)
  # Modify the server, remove the keys of root and targets roles
  try:
    server_fileList = os.listdir(server_path)
    for files in server_fileList:
      files_path = os.path.join(server_path, files)
      if files == 'metadata.staged':
        if os.path.isdir(files_path):
          shutil.rmtree(files_path)
          continue
        os.remove(files_path)
      if files == 'metadata' and os.path.isdir(files_path):
        role_path = os.path.join(server_path, "metadata")
        role_fileList = os.listdir(role_path)
        for roles in role_fileList:
          roles_path = os.path.join(role_path, roles)
          if roles == 'root.txt':
            os.remove(roles_path)
            continue
          if roles == 'targets.txt':
            os.remove(roles_path)
            continue
  except Exception, e:
    print 'Error,', str(e)
    sys.exit(0)

def update_metadata(basic_directory, flag):
  print '*** Hello ...'
  if flag is True:
    mr = Make_repository()
    mr.modify_targets_file(basic_directory, flag)
    mr.make_metadata_dir()
    mr.make_client_dir()
  else:
    mr = Make_repository()
    mr.modify_targets_file(basic_directory, flag)
    mr.make_metadata_dir()
    mr.make_client_dir()

def generate_file_dir(basic_directory, flag):
  print '*** Hello ...'
  base_path = os.path.dirname(__file__)
  basic_path = os.path.join(base_path, basic_directory)
  if not os.path.exists(basic_path):
    print 'Create directory ', basic_directory
    os.makedirs(basic_path)

  if flag is True:
    django_path = os.path.join(basic_path, "django")
    if not os.path.exists(django_path):
      print 'Create directory django'
      os.makedirs(django_path)

def generate_repository(basic_directory, flag):
  print '*** Hello ...'
  #generate_metadata(basic_directory, flag)

  # If writemetainfo_dir is not found, then input the specific dir
  base_path = os.path.dirname(__file__)
  writemetainfo_dir_path = os.path.join(base_path, "writemetainfo_dir")
  if not os.path.exists(writemetainfo_dir_path):
    print 'Directory "writemetainfo_dir" does not exist.'
    while True:
      writemetainfo_dir_path = raw_input('Input writemetainfo directory:')
      if os.path.exists(writemetainfo_dir_path):
        print 'writemetainfo path: ', writemetainfo_dir_path
        break
      else:
        print 'Directory is not found or the path is invalid!'

  # Input key pairs for metainfo generation, default is lw1378.privatekey and lw1378.publickey
  privatekey_path = os.path.join(base_path, "lw1378.privatekey")
  if not os.path.exists(privatekey_path):
    print 'privatekey for metainfo generation does not exist.'
    while True:
      privatekey_path = raw_input('Input privatekey path:')
      if os.path.exists(privatekey_path):
        print 'privatekey path: ', privatekey_path
        break
      else:
        print 'Privatekey is not found.'

  publickey_path = os.path.join(base_path, "lw1378.publickey")
  if not os.path.exists(publickey_path):
    print 'publickey for metainfo generation does not exist.'
    while True:
      publickey_path = raw_input('Input publickey path:')
      if os.path.exists(publickey_path):
        print 'publickey path: ', publickey_path
        break
      else:
        print 'Publickey is not found.' 

  # Input server path
  while True:
    server_path = raw_input('Input Server path:')
    if os.path.exists(server_path):
      print 'Server path: ', server_path
      break
    else:
      print 'Server path is either invalid or server path does not exist!'

  # Input client path
  while True:
    client_path = raw_input('Input client path:')
    if os.path.exists(client_path):
      print 'Clent path: ', client_path
      break
    else:
      print 'client path is either invalid or client path does not exist!'
  
  # Now we have three paths and two parameters
  # 1. writemetainfo_dir path
  # 2. server_path
  # 3. client_path
  # 4. private key for metainfo generation
  # 5. public key for metainfo generation

  # First we generate a new temp targets directory
  if os.path.exists(basic_directory):
    shutil.rmtree(basic_directory)
  generate_file_dir(basic_directory, flag)
  # Then we might first want to generate a new metainfo for new files
  create_metainfo_file(privatekey_path, publickey_path)
  # Then we need to copy files with metainfo into our temp targets directory
  writemetainfo_dir2basic_dir(writemetainfo_dir_path, basic_directory, flag)
  # Now we can start generate a new repository
  generate_metadata(basic_directory, flag)
  # Update the client and server
  rep_path = os.path.join(base_path, "path/to/repository")

  copy_files(rep_path, server_path)
  # Modify the server, remove the keys of root and targets roles
  try:
    server_fileList = os.listdir(server_path)
    for files in server_fileList:
      files_path = os.path.join(server_path, files)
      if files == 'metadata.staged':
        if os.path.isdir(files_path):
          shutil.rmtree(files_path)
          continue
        os.remove(files_path)
      if files == 'metadata' and os.path.isdir(files_path):
        role_path = os.path.join(server_path, "metadata")
        role_fileList = os.listdir(role_path)
        for roles in role_fileList:
          roles_path = os.path.join(role_path, roles)
          if roles == 'root.txt':
            os.remove(roles_path)
            continue
          if roles == 'targets.txt':
            os.remove(roles_path)
            continue
  except Exception, e:
    print 'Error,', str(e)
    sys.exit(0)

  cli_path = os.path.join(base_path, "path/to/client")
  copy_files(cli_path, client_path)

def update_repository(basic_directory, flag):
  print '*** Hello ...'
  #generate_metadata(basic_directory, flag)

  # If writemetainfo_dir is not found, then input the specific dir
  base_path = os.path.dirname(__file__)
  writemetainfo_dir_path = os.path.join(base_path, "writemetainfo_dir")
  if not os.path.exists(writemetainfo_dir_path):
    print 'Directory "writemetainfo_dir" does not exist.'
    while True:
      writemetainfo_dir_path = raw_input('Input writemetainfo directory:')
      if os.path.exists(writemetainfo_dir_path):
        print 'writemetainfo path: ', writemetainfo_dir_path
        break
      else:
        print 'Directory is not found or the path is invalid!'

  # Input key pairs for metainfo generation, default is lw1378.privatekey and lw1378.publickey
  privatekey_path = os.path.join(base_path, "lw1378.privatekey")
  if not os.path.exists(privatekey_path):
    print 'privatekey for metainfo generation does not exist.'
    while True:
      privatekey_path = raw_input('Input privatekey path:')
      if os.path.exists(privatekey_path):
        print 'privatekey path: ', privatekey_path
        break
      else:
        print 'Privatekey is not found.'

  publickey_path = os.path.join(base_path, "lw1378.publickey")
  if not os.path.exists(publickey_path):
    print 'publickey for metainfo generation does not exist.'
    while True:
      publickey_path = raw_input('Input publickey path:')
      if os.path.exists(publickey_path):
        print 'publickey path: ', publickey_path
        break
      else:
        print 'Publickey is not found.' 

  # Input server path
  while True:
    server_path = raw_input('Input Server path:')
    if os.path.exists(server_path):
      print 'Server path: ', server_path
      break
    else:
      print 'Server path is either invalid or server path does not exist!'

  # First we generate a new temp targets directory
  if os.path.exists(basic_directory):
    shutil.rmtree(basic_directory)
  generate_file_dir(basic_directory, flag)
  # Then we might first want to generate a new metainfo for new files
  create_metainfo_file(privatekey_path, publickey_path)

  writemetainfo_dir2basic_dir(writemetainfo_dir_path, basic_directory, flag)
  # Update metadata file
  update_metadata(basic_directory, flag)
  # Update the client and server
  rep_path = os.path.join(base_path, "path/to/repository")
  copy_files(rep_path, server_path)
  # Modify the server, remove the keys of root and targets roles
  try:
    server_fileList = os.listdir(server_path)
    for files in server_fileList:
      files_path = os.path.join(server_path, files)
      if files == 'metadata.staged':
        if os.path.isdir(files_path):
          shutil.rmtree(files_path)
          continue
        os.remove(files_path)
      if files == 'metadata' and os.path.isdir(files_path):
        role_path = os.path.join(server_path, "metadata")
        role_fileList = os.listdir(role_path)
        for roles in role_fileList:
          roles_path = os.path.join(role_path, roles)
          if roles == 'root.txt':
            os.remove(roles_path)
            continue
          if roles == 'targets.txt':
            os.remove(roles_path)
            continue
  except Exception, e:
    print 'Error,', str(e)
    sys.exit(0)

def writemetainfo_dir2basic_dir(writemetainfo_dir_path, basic_directory, flag):
  # If we don't use delegation, then it would be easy for this step
  if not flag:
    # Copy all files in writemetainfo_dir to temp targets directory
    copy_files(writemetainfo_dir_path, basic_directory)
  else:
    # If we use delegation now, the we should decide which directory we want to put into.
    print 'With delegation, you have to decide files in targets and in django directories.'
    print 'You could either choose files in writemetainfo dir or other files.'
    print 'You could add files by input the item index.'
    print '1. List all files in writemetainfo_dir.'
    print '2. Add files in writemetainfo_dir to temp 1.targets or 2.django, syntax:'
    print '   From, To  -->  file_index, dst_dir_index'
    print '3. Add files in writemetainof_dir to temp targets dir, syntax: none'
    print '4. Add files from other places to django delegation directory, syntax:'
    print '   directly input file path'
    print '5. exit'
    wr_fileList = os.listdir(writemetainfo_dir_path)
    while True:
      main_op = input("Please enter the index:")
      if not type(main_op) is int:
        print 'Input should be a index integer!'
        continue
      elif main_op > 5 or main_op < 1:
        print 'Input index must between 1 and 5!'
        continue
      if main_op == 1:
        print 'Files in writemetainfo_dir'
        for index in range(0, len(wr_fileList)):
          print index, wr_fileList[index]
        continue
      if main_op == 2:
        print 'Add files into 1. targets, 2. django'
        try:
          command_string = raw_input("Please input the index of files and dir that you want to input:")
          file_index = command_string.split(",")[0]
          dir_index = command_string.split(",")[-1]
          file_index = file_index.replace(" ","")
          dir_index = dir_index.replace(" ", "")
          files_path = os.path.join(writemetainfo_dir_path, wr_fileList[int(file_index)])
          if int(dir_index) == 1:
            copy_files_nd(wr_fileList[int(file_index)], files_path, basic_directory)
            print 'Successfully copy files to directory'
          else:
            dir_path = os.path.join(base_path, basic_directory)
            dir_path = os.path.join(dir_path, "django")
            copy_files_nd(wr_fileList[int(file_index)], files_path, dir_path)
            print 'Successfully copy files to directory'
        except Exception, e:
          print 'Failed to achieve the goal, please try again!,', str(e)
          continue
      if main_op == 3:
        print 'Copy all files in writemetainfo_dir to temp targets dir'
        copy_files(writemetainfo_dir_path, basic_directory)
        print 'Complete copying ...'
        continue
      if main_op == 4:
        files_path = raw_input("Input file complete path:") 
        if not os.path.exists(files_path):
          print 'File does not exist!'
          continue
        dir_path = os.path.join(basic_directory, "django")
        copy_files_nd(files_path.split("/")[-1], files_path, dir_path)
        print 'Complete copying ...'
      if main_op == 5:
        break

def help_info():
  print '*** Hello ...'
  print '--Help info--'
  print 'Usage: '
  print '"""'
  print 'before generate new repository directory, you should make sure that there'
  print 'is a basic legal temp directory to put your update files, you could create by'
  print 'yourself, or use "generate_file_dir" to generate a directory and just put your'
  print 'files into the directory.'
  print '1. Generate TUF repository, syntax:'
  print '$python repository_operator.py --generate_repository directory_name'
  print '2. Genrerate new TUF repository for update, syntax:'
  print '$python repository_operator.py --update_repository directory_name'
  #print '3. Generate temp copy directory, syntax:'
  #print '$python repository_operator.py --generate_file_dir directory_name'
  print '3. Generate TUF repository without delegations, syntax:'
  print '$python repository_operator.py --generate_repository -nd directory_name'
  print '4. Generate new TUF repository for update without delegations, syntax:'
  print '$python repository_operator.py --update_repository -nd directory_name'
  #print '6. Generate temp copy directory, syntax:'
  #print '$python repository_operator.py --generate_file_dir -nd directory_name'
  print '5. Update and refresh the timestamp roles expire date, syntax:'
  print '$python repository_operator.py --refresh_timestamp'
  print '6. Update and refresh the release roles expire date, syntax:'
  print '$python repository_operator.py --refresh_release'
  print '7. Update and refresh the targets roles expire date, syntax:'
  print '$python repository_operator.py --refresh_targets'
  print '8. Update and refresh the root roles expire date, syntax:'
  print '$python repository_operator.py --refresh_root'
  print '"""'

if __name__ == '__main__':
  if len(sys.argv) > 4:
    print 'Too many args! Use "--help" to get more info.'
    sys.exit(0)
  elif len(sys.argv) == 4:
    if sys.argv[1] == '--generate_repository' and sys.argv[2] == '-nd':
      generate_repository(str(sys.argv[3]), False)
    elif sys.argv[1] == '--update_repository' and sys.argv[2] == '-nd':
      update_repository(str(sys.argv[3]), False)
    #elif sys.argv[1] == '--generate_file_dir' and sys.argv[2] == '-nd':
      #generate_file_dir(str(sys.argv[3]), False)
    else:
      print 'Illegal args! Use "--help" to get more info.'
      sys.exit(0)
  elif len(sys.argv) == 3:
    if sys.argv[1] == '--generate_repository':
      generate_repository(str(sys.argv[2]), True)
    elif sys.argv[1] == '--update_repository':
      update_repository(str(sys.argv[2]), True)
    #elif sys.argv[1] == '--generate_file_dir':
      #generate_file_dir(str(sys.argv[2]), True)
    else:
      print 'Illegal args! Use "--help" to get more info.'
  elif len(sys.argv) == 2:
    if sys.argv[1] == '--refresh_timestamp':
      refresh_timestamp_expire_data()
    elif sys.argv[1] == '--refresh_release':
      refresh_release_expire_data()
    elif sys.argv[1] == '--refresh_targets':
      refresh_targets_expire_data()
    elif sys.argv[1] == '--refresh_root':
      refresh_root_expire_data()
    elif sys.argv[1] == '--help':
      help_info()
      sys.exit(0)
    else: 
      print 'Illegal args! Use "--help" to get more info.'
      sys.exit(0)
  else:
    print 'Use "--help" to get more info.'
    sys.exit(0)