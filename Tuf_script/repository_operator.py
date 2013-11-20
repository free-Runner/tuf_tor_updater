import os
import sys
import shutil
from tuf.libtuf import *

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
    # # Load the signing keys of the remaining roles
    repository.root.load_signing_key(private_root_key)
    repository.root.load_signing_key(private_root_key2)
    repository.targets.load_signing_key(private_targets_key)
    repository.release.load_signing_key(private_release_key)
    repository.timestamp.load_signing_key(private_timestamp_key)
    # Set the expiration date of the timestamp role.
    repository.timestamp.expiration = "2014-10-28 12:08:00"
    repository.targets.compressions = ["gz"]
    repository.release.compressions = ["gz"]

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

  def directory_operation(self):
    repository = load_repository(self.repository_path)
    self._add_targets_file(repository)
    self._delegation_operations(repository)

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

  def _modify_targets_file(self, label, filename, repository):
    if label != 'add' and label != 'remove':
      print 'label must be add or remove !'
      sys.exit(0)

    if label == 'add':
      repository_current = os.path.join("path/to/repository/targets", filename)
      repository.targets.add_target(repository_current)
      # Write the repository
      try:
        repository.write()
      except tuf.Error, e:
        print 'Failed to achieve the goal as ', str(e)

    if label == 'remove':
      repository_current = os.path.join("path/to/repository/targets", filename)
      repository.targets.remove_target(repository_current)
      # Write the repository
      try:
        repository.write()
      except tuf.Error, e:
        print 'Failed to achieve the goal as ', str(e)

  def _delegation_operations(self, repository):
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
    repository.targets.add_targets(list_of_targets)
    repository.targets.unclaimed.django.compressions = ["gz"]
    # Write the repository
    try:
      repository.write()
    except tuf.Error, e:
      print 'Failed to achieve the goal as ', str(e)

    repository.targets.unclaimed.delegate("flask", [public_unclaimed_key], [])
    repository.targets.unclaimed.revoke("flask")
    # Write the repository
    try:
      repository.write()
    except tuf.Error, e:
      print 'Failed to achieve the goal as ', str(e)

    # Create a metadata directory and copy all files into it
    metadata_staged_path = os.path.join(self.repository_path, "metadata.staged")
    metadata_path = os.path.join(self.repository_path, "metadata")

    if not os.path.exists(metadata_staged_path):
      print "illegal repository, try to build it again !"
      sys.exit(0)
    if not os.path.exists(metadata_path):
      os.makedirs(metadata_path)

    # Copy all files.
    self._copy_files(metadata_staged_path, metadata_path)

  def make_client_dir(self):
    print '>>> Making client directory ...'
    # Create Client
    create_tuf_client_directory("path/to/repository/", "path/to/client/")

def generate_repository(basic_directory):
  print '*** Hello ...'
  mr = Make_repository()
  mr.init_state()
  mr.create_rsa_keys()
  mr.create_repository_metadata()
  mr.create_targets_file(basic_directory)
  mr.directory_operation()
  mr.make_client_dir()
  print '*** Process complete ...'

def generate_file_dir(basic_directory):
  print '*** Hello ...'
  base_path = os.path.dirname(__file__)
  basic_path = os.path.join(base_path, basic_directory)
  if not os.path.exists(basic_path):
    print 'Create directory ', basic_directory
    os.makedirs(basic_path)

  django_path = os.path.join(basic_path, "django")
  if not os.path.exists(django_path):
    print 'Create directory django'
    os.makedirs(django_path)

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
  print '$python repository_operator.py --generate_repository [directory_name]'
  print '*** If directory_name is not given, '
  print 'then use the default value -> targets_files.'
  print '2. Generate temp copy directory, syntax:'
  print '$python repository_operator.py --generate_file_dir [directory_name]'
  print '*** If directory_name is not given, '
  print 'then use the default value -> targets_files.'
  print '"""'

if __name__ == '__main__':
  if len(sys.argv) > 3:
    print 'Too many args! Use "--help" to get more info.'
    sys.exit(0)
  elif len(sys.argv) == 3:
    if sys.argv[1] == '--generate_repository':
      generate_repository(str(sys.argv[2]))
    elif sys.argv[1] == '--generate_file_dir':
      generate_file_dir(str(sys.argv[2]))
    else:
      print 'Illegal args! Use "--help" to get more info.'
      sys.exit(0)
  elif len(sys.argv) == 2:
    if sys.argv[1] == '--generate_repository':
      generate_repository("targets_files")
    elif sys.argv[1] == '--generate_file_dir':
      generate_file_dir("targets_files")
    elif sys.argv[1] == '--help':
      help_info()
      sys.exit(0)
    else: 
      print 'Illegal args! Use "--help" to get more info.'
      sys.exit(0)
  else:
    print 'Use "--help" to get more info.'
    sys.exit(0)