"""
<Program Name>
  ed25519_keys.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  September 24, 2013.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  The goal of this module is to support ed25519 signatures.  ed25519 is an
  elliptic-curve public key signature scheme, its main strength being small
  signatures (64 bytes) and small public keys (32 bytes).
  http://ed25519.cr.yp.to/
  
  'tuf/ed25519_keys.py' calls 'ed25519/ed25519.py', which is the pure Python
  implementation of ed25519 optimized for a faster runtime.
  The Python reference implementation is concise, but very slow (verifying
  signatures takes ~9 seconds on an Intel core 2 duo @ 2.2 ghz x 2).  The
  optimized version can verify signatures in ~2 seconds.

  http://ed25519.cr.yp.to/software.html
  https://github.com/pyca/ed25519
  
  Optionally, ed25519 cryptographic operations may be executed by PyNaCl, which
  is a Python binding to the NaCl library and is faster than the pure python
  implementation.  Verifying signatures can take approximately 0.0009 seconds.
  PyNaCl relies on the libsodium C library.
 
  https://github.com/pyca/pynacl
  https://github.com/jedisct1/libsodium
  http://nacl.cr.yp.to/
  
  The ed25519-related functions included here are generate(), create_signature()
  and verify_signature().  The 'ed25519' and PyNaCl (i.e., 'nacl') modules used 
  by ed25519_keys.py generate the actual ed25519 keys and the functions listed
  above can be viewed as an easy-to-use public interface.
 """

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division

# 'binascii' required for hexadecimal conversions.  Signatures and
# public/private keys are hexlified.
import binascii

# 'os' required to generate OS-specific randomness (os.urandom) suitable for
# cryptographic use.
# http://docs.python.org/2/library/os.html#miscellaneous-functions
import os

# Import the python implementation of the ed25519 algorithm provided by pyca,
# which is an optimized version of the one provided by ed25519's authors.
# Note: The pure Python version do not include protection against side-channel
# attacks.  Verifying signatures can take approximately 2 seconds on a intel
# core 2 duo @ 2.2 ghz x 2).  Optionally, the PyNaCl module may be used to
# speed up ed25519 cryptographic operations.
# http://ed25519.cr.yp.to/software.html
# https://github.com/pyca/ed25519
# https://github.com/pyca/pynacl
#
# PyNaCl's 'cffi' dependency may thrown an 'IOError' exception when
# importing 'nacl.signing'.
try:
  import nacl.signing
  import nacl.encoding
except (ImportError, IOError):
  pass

# The optimized pure Python implementation of ed25519 provided by TUF.  If
# PyNaCl cannot be imported and an attempt to use is made in this module, a
# 'tuf.UnsupportedLibraryError' exception is raised.  
import ed25519.ed25519

import tuf

# Digest objects needed to generate hashes.
import tuf.hash

# Perform object format-checking.
import tuf.formats

# Supported ed25519 signing methods.  'ed25519-python' is the pure Python
# implementation signing method.  'ed25519-pynacl' (i.e., 'nacl' module) is the
# (libsodium+Python bindings) implementation signing method. 
_SUPPORTED_ED25519_SIGNING_METHODS = ['ed25519-python', 'ed25519-pynacl']


def generate_public_and_private(use_pynacl=False):
  """
  <Purpose> 
    Generate a pair of ed25519 public and private keys.
    The public and private keys returned conform to
    'tuf.formats.ED25519PULIC_SCHEMA' and 'tuf.formats.ED25519SEED_SCHEMA',
    respectively, and have the form:
    
    '\xa2F\x99\xe0\x86\x80%\xc8\xee\x11\xb95T\xd9\...'

    An ed25519 seed key is a random 32-byte string.  Public keys are also 32
    bytes.

    >>> public, private = generate_public_and_private(use_pynacl=False)
    >>> tuf.formats.ED25519PUBLIC_SCHEMA.matches(public)
    True
    >>> tuf.formats.ED25519SEED_SCHEMA.matches(private)
    True
    >>> public, private = generate_public_and_private(use_pynacl=True)
    >>> tuf.formats.ED25519PUBLIC_SCHEMA.matches(public)
    True
    >>> tuf.formats.ED25519SEED_SCHEMA.matches(private)
    True

  <Arguments>
    use_pynacl:
      True, if the ed25519 keys should be generated with PyNaCl.  False, if the
      keys should be generated with the pure Python implementation of ed25519
      (slower).

  <Exceptions>
    tuf.FormatError, if 'use_pynacl' is not a Boolean.

    tuf.UnsupportedLibraryError, if the PyNaCl ('nacl') module is unavailable
    and 'use_pynacl' is True. 

    NotImplementedError, if a randomness source is not found by 'os.urandom'.

  <Side Effects>
    The ed25519 keys are generated by first creating a random 32-byte seed
    with os.urandom() and then calling ed25519's
    ed25519.25519.publickey(seed) or PyNaCl's nacl.signing.SigningKey().

  <Returns>
    A (public, private) tuple that conform to 'tuf.formats.ED25519PUBLIC_SCHEMA'
    and 'tuf.formats.ED25519SEED_SCHEMA', respectively.
  """
  
  # Does 'use_pynacl' have the correct format?
  # This check will ensure 'use_pynacl' conforms to 'tuf.formats.TOGGLE_SCHEMA'.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.TOGGLE_SCHEMA.check_match(use_pynacl)

  # Generate ed25519's seed key by calling os.urandom().  The random bytes
  # returned should be suitable for cryptographic use and is OS-specific.
  # Raise 'NotImplementedError' if a randomness source is not found.
  # ed25519 seed keys are fixed at 32 bytes (256-bit keys).
  # http://blog.mozilla.org/warner/2011/11/29/ed25519-keys/ 
  seed = os.urandom(32)
  public = None

  if use_pynacl:
    # Generate the public key.  PyNaCl (i.e., 'nacl' module) performs
    # the actual key generation.
    try:
      nacl_key = nacl.signing.SigningKey(seed)
      public = str(nacl_key.verify_key)
    except NameError:
      message = 'The PyNaCl library and/or its dependencies unavailable.'
      raise tuf.UnsupportedLibraryError(message)

  # Use the pure Python implementation of ed25519. 
  else: 
    public = ed25519.ed25519.publickey(seed)
  
  return public, seed





def create_signature(public_key, private_key, data, use_pynacl=False):
  """
  <Purpose>
    Return a (signature, method) tuple, where the method is either:
    'ed25519-python' if the signature is generated by the pure python
    implemenation, or 'ed25519-pynacl' if generated by 'nacl'.
    signature conforms to 'tuf.formats.ED25519SIGNATURE_SCHEMA', and has the
    form:
    
    '\xae\xd7\x9f\xaf\x95{bP\x9e\xa8YO Z\x86\x9d...'

    A signature is a 64-byte string.

    >>> public, private = generate_public_and_private(use_pynacl=False)
    >>> data = 'The quick brown fox jumps over the lazy dog'
    >>> signature, method = \
        create_signature(public, private, data, use_pynacl=False)
    >>> tuf.formats.ED25519SIGNATURE_SCHEMA.matches(signature)
    True
    >>> method == 'ed25519-python'
    True
    >>> signature, method = \
        create_signature(public, private, data, use_pynacl=True)
    >>> tuf.formats.ED25519SIGNATURE_SCHEMA.matches(signature)
    True
    >>> method == 'ed25519-pynacl'
    True

  <Arguments>
    public:
      The ed25519 public key, which is a 32-byte string.
    
    private:
      The ed25519 private key, which is a 32-byte string.

    data:
      Data object used by create_signature() to generate the signature.
    
    use_pynacl:
      True, if the ed25519 signature should be generated with PyNaCl.  False,
      if the signature should be generated with the pure Python implementation
      of ed25519 (much slower).

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

    tuf.CryptoError, if a signature cannot be created.

  <Side Effects>
    ed25519.ed25519.signature() or nacl.signing.SigningKey.sign() called to
    generate the actual signature.

  <Returns>
    A signature dictionary conformat to 'tuf.format.SIGNATURE_SCHEMA'.
    ed25519 signatures are 64 bytes, however, the hexlified signature is
    stored in the dictionary returned.
  """
  
  # Does 'public_key' have the correct format?
  # This check will ensure 'public_key' conforms to
  # 'tuf.formats.ED25519PUBLIC_SCHEMA', which must have length 32 bytes.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.ED25519PUBLIC_SCHEMA.check_match(public_key)

  # Is 'private_key' properly formatted?
  tuf.formats.ED25519SEED_SCHEMA.check_match(private_key)
  
  # Is 'use_pynacl' properly formatted?
  tuf.formats.TOGGLE_SCHEMA.check_match(use_pynacl)
  
  # Signing the 'data' object requires a seed and public key.
  # 'ed25519.ed25519.py' generates the actual 64-byte signature in pure Python.
  # nacl.signing.SigningKey.sign() generates the signature if 'use_pynacl'
  # is True.
  public = public_key
  private = private_key

  method = None 
  signature = None
 
  # The private and public keys have been validated above by 'tuf.formats' and
  # should be 32-byte strings.
  if use_pynacl:
    method = 'ed25519-pynacl'
    try:
      nacl_key = nacl.signing.SigningKey(private)
      nacl_sig = nacl_key.sign(data)
      signature = nacl_sig.signature
    
    except NameError:
      message = 'The PyNaCl library and/or its dependencies unavailable.'
      raise tuf.UnsupportedLibraryError(message)
    
    except (ValueError, nacl.signing.CryptoError):
      message = 'An "ed25519-pynacl" signature could not be created.'
      raise tuf.CryptoError(message)
   
  # Generate an "ed25519-python" (i.e., pure python implementation) signature.
  else:
    # ed25519.ed25519.signature() requires both the seed and public keys.
    # It calculates the SHA512 of the seed key, which is 32 bytes.
    method = 'ed25519-python'
    try:
      signature = ed25519.ed25519.signature(data, private, public)
   
    # 'Exception' raised by ed25519.py for any exception that may occur.
    except Exception, e:
      message = 'An "ed25519-python" signature could not be generated.'
      raise tuf.CryptoError(message)
  
  return signature, method





def verify_signature(public_key, method, signature, data, use_pynacl=False):
  """
  <Purpose>
    Determine whether the private key corresponding to 'public_key' produced
    'signature'.  verify_signature() will use the public key, the 'method' and
    'sig', and 'data' arguments to complete the verification.

    >>> public, private = generate_public_and_private(use_pynacl=False)
    >>> data = 'The quick brown fox jumps over the lazy dog'
    >>> signature, method = \
        create_signature(public, private, data, use_pynacl=False)
    >>> verify_signature(public, method, signature, data, use_pynacl=False)
    True
    >>> verify_signature(public, method, signature, data, use_pynacl=True)
    True
    >>> bad_data = 'The sly brown fox jumps over the lazy dog'
    >>> bad_signature, method = \
        create_signature(public, private, bad_data, use_pynacl=False)
    >>> verify_signature(public, method, bad_signature, data, use_pynacl=False)
    False
  
  <Arguments>
    public_key:
      The public key is a 32-byte string.

    method:
      'ed25519-python' if the signature was generated by the pure python
      implementation and 'ed25519-pynacl' if generated by 'nacl'.
      
    signature:
      The signature is a 64-byte string. 
      
    data:
      Data object used by tuf.ed25519_keys.create_signature() to generate
      'signature'.  'data' is needed here to verify the signature.
    
    use_pynacl:
      True, if the ed25519 signature should be verified by PyNaCl.  False,
      if the signature should be verified with the pure Python implementation
      of ed25519 (slower).

  <Exceptions>
    tuf.UnknownMethodError.  Raised if the signing method used by
    'signature' is not one supported by tuf.ed25519_keys.create_signature().
    
    tuf.FormatError. Raised if the arguments are improperly formatted. 

  <Side Effects>
    ed25519.ed25519.checkvalid() called to do the actual verification.
    nacl.signing.VerifyKey.verify() called if 'use_pynacl' is True.

  <Returns>
    Boolean.  True if the signature is valid, False otherwise.
  """
  
  # Does 'public_key' have the correct format?
  # This check will ensure 'public_key' conforms to
  # 'tuf.formats.ED25519PUBLIC_SCHEMA', which must have length 32 bytes.
  # Raise 'tuf.FormatError' if the check fails.
  tuf.formats.ED25519PUBLIC_SCHEMA.check_match(public_key)

  # Is 'method' properly formatted?
  tuf.formats.NAME_SCHEMA.check_match(method)
  
  # Is 'signature' properly formatted?
  tuf.formats.ED25519SIGNATURE_SCHEMA.check_match(signature)
  
  # Is 'use_pynacl' properly formatted?
  tuf.formats.TOGGLE_SCHEMA.check_match(use_pynacl)

  # Verify 'signature'.  Before returning the Boolean result,
  # ensure 'ed25519-python' or 'ed25519-pynacl' was used as the signing method.
  # Raise 'tuf.UnsupportedLibraryError' if 'use_pynacl' is True but 'nacl' is
  # unavailable.
  public = public_key
  valid_signature = False

  if method in _SUPPORTED_ED25519_SIGNING_METHODS:
    if use_pynacl: 
      try:
        nacl_verify_key = nacl.signing.VerifyKey(public)
        nacl_message = nacl_verify_key.verify(data, signature) 
        if nacl_message == data:
          valid_signature = True
      except NameError:
        message = 'The PyNaCl library and/or its dependencies unavailable.'
        raise tuf.UnsupportedLibraryError(message)
      except nacl.signing.BadSignatureError:
        pass 
    
    # Verify signature with 'ed25519-python' (i.e., pure Python implementation). 
    else:
      try:
        ed25519.ed25519.checkvalid(signature, data, public)
        valid_signature = True
      
      # The pure Python implementation raises 'Exception' if 'signature' is
      # invalid.
      except Exception, e:
        pass
  else:
    message = 'Unsupported ed25519 signing method: '+repr(method)+'.\n'+ \
      'Supported methods: '+repr(_SUPPORTED_ED25519_SIGNING_METHODS)+'.'
    raise tuf.UnknownMethodError(message)

  return valid_signature 



if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running 'ed25519_keys.py' as a standalone module.
  # python -B ed25519_keys.py
  import doctest
  doctest.testmod()
