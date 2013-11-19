from tuf.libtuf import *

# Load the repository created in the previous section.  This repository so far contains metadata for
# the top-level roles, but no targets.
repository = load_repository("./new_repo")

# Get a list of file paths in a directory, even those in sub-directories.
# This must be relative to an existing directory in the repository, otherwise throw an
# error.
list_of_targets = repository.get_filepaths_in_directory("./new_repo/targets/",recursive_walk=False, followlinks=True) 
# Add the list of target paths to the metadata of the Targets role.  Any target file paths
# that may already exist are NOT replaced.  add_targets() does not create or move target files.
repository.targets.add_targets(list_of_targets)
# Individual target files may also be added.
#repository.targets.add_target("path/to/repository/targets/file3.txt")
# The private key of the updated targets metadata must be loaded before it can be signed and
# written (Note the load_repository() call above).
private_targets_key =  import_rsa_privatekey_from_file("./keys/targets_key")
repository.targets.load_signing_key(private_targets_key)

# Due to the load_repository(), we must also load the private keys of the other top-level roles
# to generate a valid set of metadata.
private_root_key = import_rsa_privatekey_from_file("./keys/root_key")
private_release_key = import_rsa_privatekey_from_file("./keys/release_key")
private_timestamp_key = import_rsa_privatekey_from_file("./keys/timestamp_key")

repository.root.load_signing_key(private_root_key)
repository.release.load_signing_key(private_release_key)
repository.timestamp.load_signing_key(private_timestamp_key)

repository.status()
# Generate new versions of all the top-level metadata.
repository.write()
