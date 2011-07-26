import logging
import base64
import hashlib
import time
import struct
import random
import models as db

from django.contrib.auth.models import User

def validate_token(token):
    """If token is a valid authentication token for a user, return the
    associated User object.  Otherwise, return None.
    @param token  A base-64 encoded authentication token from a URL."""
    
    # The token should contain a base64 coding of a username, random number,
    # a time, and a hash of these with the user's simulation auth key.
    # First, do base64 decoding
    try:
        token = base64.b32decode(token)
    except TypeError:
        logging.debug("Rejecting token access with invalid token")
        # Invalid token
        return None
        
    # Get the username, times, random number and hash from the token
    format = "!32p3I32s"
    if struct.calcsize(format) != len(token):
        # The token is the wrong length
        logging.debug("Rejecting token access with invalid token (wrong length)")
        return None
    (username, time_start, time_end, salt, submitted_hash) = \
        struct.unpack(format, token)

    # Check that we're not outside the allowed time
    if time.time() >= time_end or time.time < time_start:
        logging.debug("Rejecting token access for %s: token has expired or is not yet valid" % username)
        return None

    # Check that a user of this name exists and, if so, get their auth_key
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        logging.debug("Rejecting token acccess for non-existent user %s" % username)
        return None
    auth_key = user.get_profile().get_sim_auth_key()

    # Check that the hash is what it should be
    format_nohash = "!32p3I64s"
    packed = struct.pack(format_nohash, str(username), time_start, time_end, salt, str(auth_key))
    expected_hash = hashlib.sha256(packed).digest()

    # Check that they match
    if expected_hash == submitted_hash:
        logging.debug("Allowing token access for %s" % username)
        return user
    else:
        logging.debug("Rejecting token access for %s with invalid hash" % username)
        logging.debug("Expected %s" % expected_hash)
        logging.debug("Got      %s" % submitted_hash)
        return None

def create_token(user, time_to_expire):
    """Creates an authentication token valid for the following time_to_expire
    seconds.
    @param user  A User object for which to create the token
    @param time_to_expire  The time in seconds from the call to create_token
    after which the token will no longer be valid
    @return base-64 string representation of the token"""

    # Get the things which make up the hash
    time_start = time.time()
    time_end = time_start + time_to_expire
    salt = random.getrandbits(32)
    username = user.username
    auth_key = user.get_profile().get_sim_auth_key()

    # Hash them
    format_nohash = "!32p3I64s"
    packed = struct.pack(format_nohash, str(username), time_start, time_end, salt, str(auth_key))
    token_hash = hashlib.sha256(packed).digest()

    # Put the times, username, salt and hash into the token
    format = "!32p3I32s"
    token = struct.pack(format, str(username), time_start, time_end, salt, token_hash)

    # Encode as base-64 and return
    return base64.b32encode(token)
