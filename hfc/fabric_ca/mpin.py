"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
"""


"""
mpin

This module use cffi to access the c functions in the mpin library.

There is also an example usage program in this file.

"""
import cffi
import platform
import os


ffi = cffi.FFI()
ffi.cdef("""
typedef struct {
unsigned int ira[21];  /* random number...   */
int rndptr;   /* ...array & pointer */
unsigned int borrow;
int pool_ptr;
char pool[32];    /* random pool */
} csprng;

typedef struct
{
    int len;
    int max;
    char *val;
} octet;


extern unsigned int MPIN_FS(void);
extern unsigned int MPIN_GS(void);
extern void MPIN_HASH_ID(int h,octet *ID,octet *HID);
extern unsigned int MPIN_GET_TIME(void);
extern void MPIN_GET_Y(int h,int t,octet *O,octet *Y);
extern int MPIN_EXTRACT_PIN(int h,octet *ID,int pin,octet *CS);
extern int MPIN_CLIENT(int h,int d,octet *ID,csprng *R,octet *x,int pin,octet *T,octet *V,octet *U,octet *UT,octet *TP, octet* MESSAGE, int t, octet *y);
extern int MPIN_CLIENT_1(int h,int d,octet *ID,csprng *R,octet *x,int pin,octet *T,octet *S,octet *U,octet *UT,octet *TP);
extern int MPIN_RANDOM_GENERATE(csprng *R,octet *S);
extern int MPIN_CLIENT_2(octet *x,octet *y,octet *V);
extern int MPIN_SERVER(int h,int d,octet *HID,octet *HTID,octet *y,octet *SS,octet *U,octet *UT,octet *V,octet *E,octet *F,octet *ID,octet *MESSAGE, int t);
extern void MPIN_SERVER_1(int h,int d,octet *ID,octet *HID,octet *HTID);
extern int MPIN_SERVER_2(int d,octet *HID,octet *HTID,octet *y,octet *SS,octet *U,octet *UT,octet *V,octet *E,octet *F);
extern int MPIN_RECOMBINE_G1(octet *Q1,octet *Q2,octet *Q);
extern int MPIN_RECOMBINE_G2(octet *P1,octet *P2,octet *P);
extern int MPIN_KANGAROO(octet *E,octet *F);
extern int MPIN_ENCODING(csprng *R,octet *TP);
extern int MPIN_DECODING(octet *TP);
extern unsigned int MPIN_today(void);
extern void MPIN_CREATE_CSPRNG(csprng *R,octet *S);
extern void MPIN_KILL_CSPRNG(csprng *R);
extern int MPIN_GET_G1_MULTIPLE(csprng *R,int type,octet *x,octet *G,octet *W);
extern int MPIN_GET_G2_MULTIPLE(csprng *R,int type,octet *x,octet *G,octet *W);
extern void MPIN_HASH_ALL(int h,octet *I,octet *U,octet *CU,octet *Y,octet *V,octet *R,octet *W,octet *H);
extern int MPIN_GET_CLIENT_SECRET(octet *S,octet *ID,octet *CS);
extern int MPIN_GET_CLIENT_PERMIT(int h,int d,octet *S,octet *ID,octet *TP);
extern int MPIN_GET_SERVER_SECRET(octet *S,octet *SS);
extern int MPIN_PRECOMPUTE(octet *T,octet *ID,octet *CP,octet *g1,octet *g2);
extern int MPIN_SERVER_KEY(int h,octet *Z,octet *SS,octet *w,octet *p,octet *I,octet *U,octet *UT,octet *K);
extern int MPIN_CLIENT_KEY(int h,octet *g1,octet *g2,int pin,octet *r,octet *x,octet *p,octet *T,octet *K);
extern void MPIN_AES_GCM_ENCRYPT(octet *K,octet *IV,octet *H,octet *P,octet *C,octet *T);
extern void MPIN_AES_GCM_DECRYPT(octet *K,octet *IV,octet *H,octet *C,octet *P,octet *T);
extern void hex2bytes(char *hex, char *bin);
extern void generateRandom(csprng*, octet*);
extern int generateOTP(csprng*);


""")

if (platform.system() == 'Windows'):
    libmpin = ffi.dlopen("libmpin.dll")
elif (platform.system() == 'Darwin'):
    libmpin = ffi.dlopen("libmpin.dylib")
else:
    libmpin = ffi.dlopen("libmpin.so")

# MPIN Group Size
PGS = libmpin.MPIN_GS()
# MPIN Field Size
PFS = libmpin.MPIN_FS()
G1 = 2 * PFS + 1
G2 = 4 * PFS
GT = 12 * PFS
# AES-GCM IV length
IVL = 12
# MPIN Symmetric Key Size
PAS = 16

# Hash function choice
SHA256 = 32
SHA384 = 48
SHA512 = 64


def to_hex(octet_value):
    """Converts an octet type into a string

    Add all the values in an octet into an array. This arrays is then
    converted to a string and hex encoded.

    Args::

        octet_value. An octet pointer type

    Returns::

        String

    Raises:
        Exception
    """
    i = 0
    val = []
    while i < octet_value.len:
        val.append(octet_value.val[i])
        i = i + 1
    return b''.join(val).hex()


def make_octet(length, value=None):
    """Generates an octet pointer

    Generates an empty octet or one filled with the input value

    Args::

        length: Length of empty octet
        value:  Data to assign to octet

    Returns::

        oct_ptr: octet pointer
        val: data associated with octet to prevent garbage collection

    Raises:

    """
    oct_ptr = ffi.new("octet*")
    if value:
        val = ffi.new("char [%s]" % len(value), value)
        oct_ptr.val = val
        oct_ptr.max = len(value)
        oct_ptr.len = len(value)
    else:
        val = ffi.new("char []", length)
        oct_ptr.val = val
        oct_ptr.max = length
        oct_ptr.len = length
    return oct_ptr, val


def today():
    """Today's date as days elapsed from the epoch

    Today's date as days elapsed from the epoch. This function uses the system clock

    Args::

    Returns::

        epoch_date: epoch days

    Raises:

    """
    return libmpin.MPIN_today()


def get_time():
    """Get time elapsed from the epoch

    Time elapsed from the epoch. This function uses the system clock

    Args::

    Returns::

        epoch_time: epoch time

    Raises:

    """
    return libmpin.MPIN_GET_TIME()


def create_csprng(seed):
    """Make a Cryptographically secure pseudo-random number generator instance

    Make a Cryptographically secure pseudo-random number generator instance

    Args::

        seed:   random seed value

    Returns::

        rng: Pointer to cryptographically secure pseudo-random number generator instance

    Raises:

    """
    seed_oct, seed_val = make_octet(None, seed)

    # random number generator
    rng = ffi.new('csprng*')
    libmpin.MPIN_CREATE_CSPRNG(rng, seed_oct)

    return rng


def hash_id(hash_type, mpin_id):
    """Hash an M-Pin Identity to an octet

    Hash an M-Pin Identity to an octet

    Args::

        mpin_id:   An octet pointer containing the M-Pin ID

    Returns::

        hash_mpin_id: hash of the M-Pin ID

    Raises:

    """
    # Hash value of mpin_id
    mpin_id1, mpin_id1_val = make_octet(None, mpin_id)
    hash_mpin_id1, hash_mpin_id1_val = make_octet(PFS)
    libmpin.MPIN_HASH_ID(hash_type, mpin_id1, hash_mpin_id1)

    hash_mpin_id_hex = to_hex(hash_mpin_id1)
    return bytes.fromhex(hash_mpin_id_hex)


def random_generate(rng):
    """Generate a random group element

    Generate a random group element

    Args::

        rng: Pointer to cryptographically secure pseudo-random number generator instance

    Returns::

        error_code: error from the C function
        s: random group element

    Raises:

    """
    s1, s_val = make_octet(PGS)
    error_code = libmpin.MPIN_RANDOM_GENERATE(rng, s1)

    s_hex = to_hex(s1)
    return error_code, bytes.fromhex(s_hex)


def get_server_secret(master_secret):
    """Create a server secret in G2 from a master secret

    Create a server secret in G2 from a master secret

    Args::

        master_secret:   An octet pointer to the master secret

    Returns::

        error_code: error from the C function
        server_secret: Server secret

    Raises:

    """
    master_secret1, master_secret1_val = make_octet(None, master_secret)
    server_secret1, server_secret1_val = make_octet(G2)
    error_code = libmpin.MPIN_GET_SERVER_SECRET(master_secret1, server_secret1)

    server_secret_hex = to_hex(server_secret1)
    return error_code, bytes.fromhex(server_secret_hex)


def recombine_G2(W1, W2):
    """Add two members from the group G2

    Add two members from the group G2

    Args::

        W1: An input member of G2
        W2: An input member of G2

    Returns::

        error_code: error from the C function
        W: An output member of G1; W = W1+W2

    Raises:

    """
    w11, w11_val = make_octet(None, W1)
    w21, w21_val = make_octet(None, W2)
    w1, w1_val = make_octet(G2)
    error_code = libmpin.MPIN_RECOMBINE_G2(w11, w21, w1)

    w_hex = to_hex(w1)
    return error_code, bytes.fromhex(w_hex)


def get_client_secret(master_secret, hash_mpin_id):
    """Create a client secret in G1 from a master secret and the hash of the M-Pin Id

    Create a client secret in G1 from a master secret and the hash of the M-Pin Id

    Args::

        master_secret:  An octet pointer to the master secret
        hash_mpin_id:   An octet pointer to the hash of the M-Pin ID

    Returns::

        error_code: error from the C function
        client_secret: Client secret

    Raises:

    """
    master_secret1, master_secret1_val = make_octet(None, master_secret)
    hash_mpin_id1, hash_mpin_id1_val = make_octet(None, hash_mpin_id)
    client_secret1, client_secret1_val = make_octet(G1)
    error_code = libmpin.MPIN_GET_CLIENT_SECRET(
        master_secret1, hash_mpin_id1, client_secret1)

    client_secret_hex = to_hex(client_secret1)
    return error_code, bytes.fromhex(client_secret_hex)


def recombine_G1(q1, q2):
    """Add two members from the group G1

    Add two members from the group G1

    Args::

        q1: An input member of G1
        q2: An input member of G1

    Returns::

        error_code: error from the C function
        q: An output member of G1 = Q1+Q2

    Raises:

    """
    q11, q11_val = make_octet(None, q1)
    q21, q21_val = make_octet(None, q2)
    q1, q1_val = make_octet(G1)
    error_code = libmpin.MPIN_RECOMBINE_G1(q11, q21, q1)

    q_hex = to_hex(q1)
    return error_code, bytes.fromhex(q_hex)


def get_client_permit(hash_type, epoch_date, master_secret, hash_mpin_id):
    """Create a time permit in G1 from a master secret, hash of the M-Pin Id and epoch days

    Create a time permit in G1 from a master secret, hash of the M-Pin Id and epoch days

    Args::

        epoch_date:  Epoch days
        master_secret:  An octet pointer to the master secret
        hash_mpin_id:   An octet pointer to the hash of the M-Pin ID

    Returns::

        error_code: error from the C function
        time_permit: Time permit

    Raises:

    """
    master_secret1, master_secret1_val = make_octet(None, master_secret)
    hash_mpin_id1, hash_mpin_id1_val = make_octet(None, hash_mpin_id)
    time_permit1, time_permit1_val = make_octet(G1)
    error_code = libmpin.MPIN_GET_CLIENT_PERMIT(
        hash_type,
        epoch_date,
        master_secret1,
        hash_mpin_id1,
        time_permit1)

    time_permit_hex = to_hex(time_permit1)
    return error_code, bytes.fromhex(time_permit_hex)


def extract_pin(hash_type, mpin_id, pin, client_secret):
    """Extract a PIN from client secret

    Extract a PIN from client secret

    Args::

        mpin_id:   M-Pin ID
        pin:   PIN input by user
        client_secret: User's client secret

    Returns::

        error_code: error from the C function
        token: Result of extracting a PIN from client secret

    Raises:

    """
    mpin_id1, mpin_id1_val = make_octet(None, mpin_id)
    client_secret1, client_secret1_val = make_octet(None, client_secret)

    error_code = libmpin.MPIN_EXTRACT_PIN(
        hash_type, mpin_id1, pin, client_secret1)

    client_secret_hex = to_hex(client_secret1)
    return error_code, bytes.fromhex(client_secret_hex)


def precompute(token, hash_mpin_id):
    """Precompute values for use by the client side of M-Pin Full

    Precompute values for use by the client side of M-Pin Full

    Args::

        token:  M-Pin token
        hash_mpin_id: hash of the M-Pin ID

    Returns::

        error_code: error from the C function
        pc1: Precomputed value one
        pc2: Precomputed value two

    Raises:

    """
    token1, token1_val = make_octet(None, token)
    hash_mpin_id1, hash_mpin_id1_val = make_octet(None, hash_mpin_id)
    pc11, pc11_val = make_octet(GT)
    pc21, pc21_val = make_octet(GT)
    error_code = libmpin.MPIN_PRECOMPUTE(
        token1, hash_mpin_id1, ffi.NULL, pc11, pc21)

    pc1_hex = to_hex(pc11)
    pc2_hex = to_hex(pc21)
    return error_code, bytes.fromhex(pc1_hex), bytes.fromhex(pc2_hex)


def client_1(hash_type, epoch_date, mpin_id, rng, x, pin, token, time_permit):
    """Perform first pass of the client side of the three pass version of the M-Pin protocol

    Perform first pass of the client side of the three pass version of the M-Pin protocol.
    If Time Permits are disabled then set epoch_date = 0.In this case UT is not generated0
    and can be set to None. If Time Permits are enabled, and PIN error detection is OFF,
    U is not generated and can be set to None. If Time Permits are enabled and PIN error
    detection is ON then U and UT are both generated.


    Args::

        epoch_date: Date, in days since the epoch. Set to 0 if Time permits disabled
        mpin_id: M-Pin ID
        rng: cryptographically secure random number generator
        pin: PIN entered by user
        token: M-Pin token
        time_permit: M-Pin time permit

    Returns::

        error_code: error from the C function
        x: Randomly generated integer if RNG!=None, otherwise must be provided as an input
        u: u = x.H(ID)
        ut: ut = x.(H(ID)H(epoch_date|H(ID)))
        v: v = CSTP, where CS is the reconstructed client secret and TP is the time permit

    Raises:

    """
    mpin_id1, mpin_id1_val = make_octet(None, mpin_id)
    token1, token1_val = make_octet(None, token)
    time_permit1, time_permit1_val = make_octet(None, time_permit)

    if rng is None:
        x1, x1_val = make_octet(None, x)
        rng = ffi.NULL
    else:
        x1, x1_val = make_octet(PGS)

    u1, u1_val = make_octet(G1)
    ut1, ut1_val = make_octet(G1)
    v1, v1_val = make_octet(G1)

    error_code = libmpin.MPIN_CLIENT_1(
        hash_type,
        epoch_date,
        mpin_id1,
        rng,
        x1,
        pin,
        token1,
        v1,
        u1,
        ut1,
        time_permit1)

    x_hex = to_hex(x1)
    u_hex = to_hex(u1)
    ut_hex = to_hex(ut1)
    v_hex = to_hex(v1)
    return error_code, bytes.fromhex(x_hex), bytes.fromhex(u_hex),\
           bytes.fromhex(ut_hex), bytes.fromhex(v_hex)


def client_2(x, y, sec):
    """Perform second pass of the client side of the 3-pass version of the M-Pin protocol

    Perform second pass of the client side of the 3-pass version of the M-Pin protocol

    Args::

        x: locally generated random number
        y: random challenge from server
        sec: CS+TP, where CS is the reconstructed client secret and TP is the time permit

    Returns::

        error_code: error from the C function
        v: v = -(x+y)(CS+TP), where CS is the reconstructed client secret and TP is the time permit

    Raises:

    """
    x1, x1_val = make_octet(None, x)
    y1, y1_val = make_octet(None, y)
    sec1, sec1_val = make_octet(None, sec)
    error_code = libmpin.MPIN_CLIENT_2(x1, y1, sec1)

    sec_hex = to_hex(sec1)
    return error_code, bytes.fromhex(sec_hex)


def client(hash_type, epoch_date, mpin_id, rng, x, pin, token,
           time_permit, message, epoch_time):
    """Perform client side of the one-pass version of the M-Pin protocol

    Perform client side of the one-pass version of the M-Pin protocol. If Time Permits are
    disabled then set epoch_date = 0.In this case UT is not generated and can be set to None.
    If Time Permits are enabled, and PIN error detection is OFF, U is not generated and
    can be set to None. If Time Permits are enabled and PIN error detection is ON then U
    and UT are both generated.

    Args::

        epoch_date: Date, in days since the epoch. Set to 0 if Time permits disabled
        mpin_id: M-Pin ID
        rng: cryptographically secure random number generator
        pin: PIN entered by user
        token: M-Pin token
        time_permit: M-Pin time permit
        message: message to be signed
        epoch_time: Epoch time in seconds

    Returns::

        error_code: error from the C function
        x: Randomly generated integer if RNG!=None, otherwise must be provided as an input
        u: u = x.H(ID)
        ut: ut = x.(H(ID)+H(epoch_date|H(ID)))
        v: v = -(x+y)(CS+TP), where CS is the reconstructed client secret and TP is the time permit
        y: y = t H(t|U) or y = H(t|UT) if Time Permits enabled

    Raises:

    """
    mpin_id1, mpin_id1_val = make_octet(None, mpin_id)
    token1, token1_val = make_octet(None, token)
    time_permit1, time_permit1_val = make_octet(None, time_permit)

    if rng is not None:
        x1, x1_val = make_octet(PGS)
    else:
        x1, x1_val = make_octet(None, x)

    if message is None:
        message1 = ffi.NULL
    else:
        message1, message1_val = make_octet(None, message)

    u1, u1_val = make_octet(G1)
    ut1, ut1_val = make_octet(G1)
    v1, v1_val = make_octet(G1)
    y1, y1_val = make_octet(PGS)

    error_code = libmpin.MPIN_CLIENT(
        hash_type,
        epoch_date,
        mpin_id1,
        rng,
        x1,
        pin,
        token1,
        v1,
        u1,
        ut1,
        time_permit1,
        message1,
        epoch_time,
        y1)

    x_hex = to_hex(x1)
    u_hex = to_hex(u1)
    ut_hex = to_hex(ut1)
    v_hex = to_hex(v1)
    y_hex = to_hex(y1)
    return error_code, bytes.fromhex(x_hex), bytes.fromhex(u_hex),\
           bytes.fromhex(ut_hex), bytes.fromhex(v_hex), bytes.fromhex(y_hex)


def get_G1_multiple(rng, type, x, P):
    """Find a random multiple of a point in G1

    Calculate W=x*P where random x < q is the order of the group of points on the curve.
    When rng is None x is passed in otherwise it is passed out.

    If type=0 then P is. point on the curve or else P is an octet that has to be
    mapped to the curve

    Args::

        rng: Pointer to cryptographically secure pseudo-random number generator instance
        type: determines type of action to be taken
        P: if type=0 a point in G1, else an octet to be mapped to G1

    Returns::

        error_code: error from the C function
        x: an output internally randomly generated if rng!=None, otherwise must be provided as an input
        W: W = x.P or W = x.M(P), where M(.) is a mapping when type = 0

    Raises:

    """
    if rng is not None:
        x1, x1_val = make_octet(PGS)
    else:
        x1, x1_val = make_octet(None, x)
    P1, P1_val = make_octet(None, P)
    W1, W1_val = make_octet(G1)
    error_code = libmpin.MPIN_GET_G1_MULTIPLE(rng, type, x1, P1, W1)

    x_hex = to_hex(x1)
    W_hex = to_hex(W1)
    return error_code, bytes.fromhex(x_hex), bytes.fromhex(W_hex)


def server_1(hash_type, epoch_date, mpin_id):
    """Perform first pass of the server side of the 3-pass version of the M-Pin protocol

    Perform first pass of the server side of the 3-pass version of the M-Pin protocol
    If Time Permits are disabled, set epoch_date = 0, and UT and HTID are not generated
    and can be set to None. If Time Permits are enabled, and PIN error detection is OFF,
    U and HID are not needed and caxn be set to None. If Time Permits are enabled,
    and PIN error detection is ON, U, UT, HID and HTID are all required.

    Args::

        epoch_date: Date, in days since the epoch. Set to 0 if Time permits disabled
        mpin_id: M-Pin ID or hash of the M-Pin ID in anonymous mode

    Returns::

        HID:  H(mpin_id). H is a map to a point on the curve
        HTID: H(mpin_id)+H(epoch_date|H(mpin_id)). H is a map to a point on the curve

    Raises:

    """
    mpin_id1, mpin_id1_val = make_octet(None, mpin_id)
    HTID1, HTID1_val = make_octet(G1)
    HID1, HID1_val = make_octet(G1)

    libmpin.MPIN_SERVER_1(hash_type, epoch_date, mpin_id1, HID1, HTID1)

    HID_hex = to_hex(HID1)
    HTID_hex = to_hex(HTID1)
    return bytes.fromhex(HID_hex), bytes.fromhex(HTID_hex)


def server_2(epoch_date, HID, HTID, y, server_secret, u, ut, v):
    """Perform third pass on the server side of the 3-pass version of the M-Pin protocol

    Perform server side of the three-pass version of the M-Pin protocol. If Time
    Permits are disabled, set epoch_date = 0, and UT and HTID are not generated and can
    be set to None. If Time Permits are enabled, and PIN error detection is OFF,
    U and HID are not needed and can be set to None. If Time Permits are enabled,
    and PIN error detection is ON, U, UT, HID and HTID are all required.

    Args::

        epoch_date: Date, in days since the epoch. Set to 0 if Time permits disabled
        HID:  H(mpin_id). H is a map to a point on the curve
        HTID: H(mpin_id)+H(epoch_date|H(mpin_id)). H is a map to a point on the curve
        y: locally generated random number
        server_secret: Server secret
        u: u = x.H(ID)
        ut: ut = x.(H(ID)+H(epoch_date|H(ID)))
        v: v = -(x+y)(CS+TP), where CS is the reconstructed client secret and TP is the time permit

    Returns::

        error_code: error from the C function
        e: value to help the Kangaroos to find the PIN error, or None if not required
        f: value to help the Kangaroos to find the PIN error, or None if not required

    Raises:

    """
    HID1, HID1_val = make_octet(None, HID)
    HTID1, HTID1_val = make_octet(None, HTID)
    y1, y1_val = make_octet(None, y)
    server_secret1, server_secret1_val = make_octet(None, server_secret)
    u1, u1_val = make_octet(None, u)
    ut1, ut1_val = make_octet(None, ut)
    v1, v1_val = make_octet(None, v)

    e1, e1_val = make_octet(GT)
    f1, f1_val = make_octet(GT)

    error_code = libmpin.MPIN_SERVER_2(
        epoch_date,
        HID1,
        HTID1,
        y1,
        server_secret1,
        u1,
        ut1,
        v1,
        e1,
        f1)

    e_hex = to_hex(e1)
    f_hex = to_hex(f1)
    return error_code, bytes.fromhex(e_hex), bytes.fromhex(f_hex)


def server(hash_type, epoch_date, server_secret,
           u, ut, v, mpin_id, message, epoch_time):
    """Perform server side of the one-pass version of the M-Pin protocol

    Perform server side of the one-pass version of the M-Pin protocol. If Time
    Permits are disabled, set epoch_date = 0, and UT and HTID are not generated and can
    be set to None. If Time Permits are enabled, and PIN error detection is OFF,
    U and HID are not needed and can be set to None. If Time Permits are enabled,
    and PIN error detection is ON, U, UT, HID and HTID are all required.

    Args::

        epoch_date: Date, in days since the epoch. Set to 0 if Time permits disabled
        server_secret: Server secret
        u: u = x.H(ID)
        ut: ut = x.(H(ID)+H(epoch_date|H(ID)))
        v: v = -(x+y)(CS+TP), where CS is the reconstructed client secret and TP is the time permit
        mpin_id: M-Pin ID or hash of the M-Pin ID in anonymous mode
        message: message to be signed
        epoch_time: Epoch time in seconds

    Returns::

        error_code: error from the C function
        HID:  H(mpin_id). H is a map to a point on the curve
        HTID: H(mpin_id)+H(epoch_date|H(mpin_id)). H is a map to a point on the curve
        e: value to help the Kangaroos to find the PIN error, or None if not required
        f: value to help the Kangaroos to find the PIN error, or None if not required
        y: y = t H(t|U) or y = H(t|UT) if Time Permits enabled used for debug

    Raises:

    """
    if message is None:
        message1 = ffi.NULL
    else:
        message1, message1_val = make_octet(None, message)

    server_secret1, server_secret1_val = make_octet(None, server_secret)
    u1, u1_val = make_octet(None, u)
    ut1, ut1_val = make_octet(None, ut)
    v1, v1_val = make_octet(None, v)
    mpin_id1, mpin_id1_val = make_octet(None, mpin_id)

    HTID1, HTID1_val = make_octet(G1)
    HID1, HID1_val = make_octet(G1)
    e1, e1_val = make_octet(GT)
    f1, f1_val = make_octet(GT)
    y1, y1_val = make_octet(PGS)

    error_code = libmpin.MPIN_SERVER(
        hash_type,
        epoch_date,
        HID1,
        HTID1,
        y1,
        server_secret1,
        u1,
        ut1,
        v1,
        e1,
        f1,
        mpin_id1,
        message1,
        epoch_time)

    HID_hex = to_hex(HID1)
    HTID_hex = to_hex(HTID1)
    e_hex = to_hex(e1)
    f_hex = to_hex(f1)
    y_hex = to_hex(y1)
    return error_code, bytes.fromhex(HID_hex), bytes.fromhex(HTID_hex),\
           bytes.fromhex(e_hex), bytes.fromhex(f_hex), bytes.fromhex(y_hex)


def kangaroo(e, f):
    """Use Pollards Kangaroos to find PIN error

    Use Pollards Kangaroos to find PIN error

    Args::

        e: a member of the group GT
        f: a member of the group GT =  E^pin_error

    Returns::

        pin_error: error in PIN or 0 if Kangaroos failed

    Raises:

    """
    e1, e1_val = make_octet(None, e)
    f1, f1_val = make_octet(None, f)
    pin_error = libmpin.MPIN_KANGAROO(e1, f1)

    return pin_error


def hash_all(hash_type, hash_mpin_id, u, ut, v, y, r, w):
    """Hash the session transcript

    Hash the session transcript

    Args::

        hash_mpin_id: An octet pointer to the hash of the M-Pin ID
        u: u = x.H(mpin_id)
        ut: ut = x.(H(ID)+H(epoch_date|H(ID)))
        v: v = -(x+y)(CS+TP), where CS is the reconstructed client secret and TP is the time permit
        y: server challenge
        r: client part response
        w: server part response

    Returns::

        hm: hash of the input values

    Raises:

    """
    if ut is None:
        ut1 = ffi.NULL
    else:
        ut1, ut1_val = make_octet(None, ut)
    hash_mpin_id1, hash_mpin_id1_val = make_octet(None, hash_mpin_id)
    u1, u1_val = make_octet(None, u)
    v1, v1_val = make_octet(None, v)
    y1, y1_val = make_octet(None, y)
    r1, r1_val = make_octet(None, r)
    w1, w1_val = make_octet(None, w)

    hm1, hm1_val = make_octet(PFS)
    libmpin.MPIN_HASH_ALL(hash_type, hash_mpin_id1,
                          u1, ut1, v1, y1, r1, w1, hm1)

    hm_hex = to_hex(hm1)
    return bytes.fromhex(hm_hex)


def client_key(hash_type, pc1, pc2, pin, r, x, hm, t):
    """Calculate Key on Client side for M-Pin Full

    Calculate Key on Client side for M-Pin Full

    Args::

        pc1: precomputed input
        pc2: precomputed input
        pin: PIN number
        r: locally generated random number
        x: locally generated random number
        hm: hash of the protocol transcript
        t: Server-side Diffie-Hellman component

    Returns::

        error_code: error code from the C function
        client_aes_key: client AES key

    Raises:

    """
    pc11, pc11_val = make_octet(None, pc1)
    pc21, pc21_val = make_octet(None, pc2)
    r1, r1_val = make_octet(None, r)
    x1, x1_val = make_octet(None, x)
    hm1, hm1_val = make_octet(None, hm)
    t1, t1_val = make_octet(None, t)
    client_aes_key1, client_aes_key_val1 = make_octet(PAS)
    error_code = libmpin.MPIN_CLIENT_KEY(
        hash_type,
        pc11,
        pc21,
        pin,
        r1,
        x1,
        hm1,
        t1,
        client_aes_key1)

    client_aes_key_hex = to_hex(client_aes_key1)
    return error_code, bytes.fromhex(client_aes_key_hex)


def server_key(hash_type, z, server_secret, w, hm, HID, u, ut):
    """Calculate Key on Server side for M-Pin Full

    Calculate Key on Server side for M-Pin Full.Uses UT internally for the
    key calculation or uses U if UT is set to None

    Args::

        z: Client-side Diffie-Hellman component
        server_secret: server secret
        w: random number generated by the server
        hm: hash of the protocol transcript
        HID: H(mpin_id). H is a map to a point on the curve
        u: u = x.H(ID)
        ut: ut = x.(H(ID)+H(epoch_date|H(ID)))

    Returns::

        error_code: error code from the C function
        server_aes_key: server AES key

    Raises:

    """
    if ut is None:
        ut1 = ffi.NULL
    else:
        ut1, ut1_val = make_octet(None, ut)
    z1, z1_val = make_octet(None, z)
    server_secret1, server_secret1_val = make_octet(None, server_secret)
    w1, w1_val = make_octet(None, w)
    hm1, hm1_val = make_octet(None, hm)
    HID1, HID1_val = make_octet(None, HID)
    u1, u1_val = make_octet(None, u)

    server_aes_key1, server_aes_key1_val = make_octet(PAS)
    error_code = libmpin.MPIN_SERVER_KEY(
        hash_type,
        z1,
        server_secret1,
        w1,
        hm1,
        HID1,
        u1,
        ut1,
        server_aes_key1)

    server_aes_key_hex = to_hex(server_aes_key1)
    return error_code, bytes.fromhex(server_aes_key_hex)


def aes_gcm_encrypt(aes_key, iv, header, plaintext):
    """AES-GCM Encryption

    AES-GCM Encryption

    Args::

        aes_key: AES Key
        iv: Initialization vector
        header: header
        plaintext: Plaintext to be encrypted

    Returns::

        ciphertext: resultant ciphertext
        tag: MAC


    Raises:

    """
    aes_key1, aes_key1_val = make_octet(None, aes_key)
    iv1, iv1_val = make_octet(None, iv)
    header1, header1_val = make_octet(None, header)
    plaintext1, plaintext1_val = make_octet(None, plaintext)
    tag1, tag1_val = make_octet(PAS)
    ciphertext1, ciphertext1_val = make_octet(len(plaintext))

    libmpin.MPIN_AES_GCM_ENCRYPT(
        aes_key1,
        iv1,
        header1,
        plaintext1,
        ciphertext1,
        tag1)
    tag = to_hex(tag1)
    ciphertext = to_hex(ciphertext1)

    return bytes.fromhex(ciphertext), bytes.fromhex(tag)


def aes_gcm_decrypt(aes_key, iv, header, ciphertext):
    """AES-GCM Decryption

    AES-GCM Deryption

    Args::

        aes_key: AES Key
        iv: Initialization vector
        header: header
        ciphertext: ciphertext

    Returns::

        plaintext: resultant plaintext
        tag: MAC

    Raises:

    """
    aes_key1, aes_key1_val = make_octet(None, aes_key)
    iv1, iv1_val = make_octet(None, iv)
    header1, header1_val = make_octet(None, header)
    ciphertext1, ciphertext1_val = make_octet(None, ciphertext)
    tag1, tag1_val = make_octet(PAS)
    plaintext1, plaintext1_val = make_octet(len(ciphertext))

    libmpin.MPIN_AES_GCM_DECRYPT(
        aes_key1,
        iv1,
        header1,
        ciphertext1,
        plaintext1,
        tag1)
    tag = to_hex(tag1)
    plaintext = to_hex(plaintext1)

    return bytes.fromhex(plaintext), bytes.fromhex(tag)


def generate_otp(rng):
    """Generate a random six digit one time password

    Generate a random six digit one time password

    Args::

        rng: Pointer to cryptographically secure pseudo-random number generator instance

    Returns::

        OTP: One time password

    Raises:

    """
    OTP = libmpin.generateOTP(rng)

    return OTP


def generate_random(rng, length):
    """Generate a random string

    Generate a random string

    Args::

        rng: Pointer to cryptographically secure pseudo-random number generator instance
        length: Gives length of random byte array

    Returns::

        random_value: Random value

    Raises:

    """
    random_value1, random_value1_val = make_octet(length)
    libmpin.generateRandom(rng, random_value1)

    random_value_hex = to_hex(random_value1)
    return bytes.fromhex(random_value_hex)


if __name__ == "__main__":
    # Print hex values
    DEBUG = False

    # Require user input
    INPUT = True

    ONE_PASS = False
    TIME_PERMITS = True
    MPIN_FULL = True
    PIN_ERROR = True
    USE_ANONYMOUS = False

    HASH_TYPE_MPIN = SHA256

    if TIME_PERMITS:
        date = today()
    else:
        date = 0

    # Seed
    seedHex = "b75e7857fa17498c333d3c8d42e10f8c3cb8a66f7a84d85f86cd5acb537fa211"
    seed = bytes.fromhex(seedHex)

    # random number generator
    rng = create_csprng(seed)

    # Identity
    if INPUT:
        mpin_id = input("Please enter identity:")
    else:
        mpin_id = "user@miracl.com"

    # Hash mpin_id
    hash_mpin_id = hash_id(HASH_TYPE_MPIN, mpin_id)
    if DEBUG:
        print("mpin_id: %s" % mpin_id.encode("hex"))
        print("hash_mpin_id: %s" % hash_mpin_id.hex())

    if USE_ANONYMOUS:
        pID = hash_mpin_id
    else:
        pID = mpin_id

    # Generate master secret for MIRACL and Customer
    rtn, ms1 = random_generate(rng)
    if rtn != 0:
        print("random_generate(rng) Error %s", rtn)
    rtn, ms2 = random_generate(rng)
    if rtn != 0:
        print("random_generate(rng) Error %s", rtn)
    if DEBUG:
        print("ms1: %s" % ms1.hex())
        print("ms2: %s" % ms2.hex())

    # Generate server secret shares
    rtn, ss1 = get_server_secret(ms1)
    if rtn != 0:
        print("get_server_secret(ms1) Error %s" % rtn)
    rtn, ss2 = get_server_secret(ms2)
    if rtn != 0:
        print("get_server_secret(ms2) Error %s" % rtn)
    if DEBUG:
        print("ss1: %s" % ss1.hex())
        print("ss2: %s" % ss2.hex())

    # Combine server secret shares
    rtn, server_secret = recombine_G2(ss1, ss2)
    if rtn != 0:
        print("recombine_G2(ss1, ss2) Error %s" % rtn)
    if DEBUG:
        print("server_secret: %s" % server_secret.hex())

    # Generate client secret shares
    rtn, cs1 = get_client_secret(ms1, hash_mpin_id)
    if rtn != 0:
        print("get_client_secret(ms1, hash_mpin_id) Error %s" % rtn)
    rtn, cs2 = get_client_secret(ms2, hash_mpin_id)
    if rtn != 0:
        print("get_client_secret(ms2, hash_mpin_id) Error %s" % rtn)
    if DEBUG:
        print("cs1: %s" % cs1.hex())
        print("cs2: %s" % cs2.hex())

    # Combine client secret shares
    rtn, client_secret = recombine_G1(cs1, cs2)
    if rtn != 0:
        print("recombine_G1(cs1, cs2) Error %s" % rtn)
    print("Client Secret: %s" % client_secret.hex())

    # Generate Time Permit shares
    if DEBUG:
        print("Date %s" % date)
    rtn, tp1 = get_client_permit(HASH_TYPE_MPIN, date, ms1, hash_mpin_id)
    if rtn != 0:
        print("get_client_permit(HASH_TYPE_MPIN, date, ms1, hash_mpin_id) Error %s" % rtn)
    rtn, tp2 = get_client_permit(HASH_TYPE_MPIN, date, ms2, hash_mpin_id)
    if rtn != 0:
        print("get_client_permit(HASH_TYPE_MPIN, date, ms2, hash_mpin_id) Error %s" % rtn)
    if DEBUG:
        print("tp1: %s" % tp1.hex())
        print("tp2: %s" % tp2.hex())

    # Combine Time Permit shares
    rtn, time_permit = recombine_G1(tp1, tp2)
    if rtn != 0:
        print("recombine_G1(tp1, tp2) Error %s" % rtn)
    if DEBUG:
        print("time_permit: %s" % time_permit.hex())

    # Client extracts PIN from secret to create Token
    if INPUT:
        PIN = int(
            input("Please enter four digit PIN to create M-Pin Token:"))
    else:
        PIN = 1234
    rtn, token = extract_pin(HASH_TYPE_MPIN, mpin_id, PIN, client_secret)
    if rtn != 0:
        print("extract_pin(HASH_TYPE_MPIN, mpin_id, PIN, token) Error %s" % rtn)
    print("Token: %s" % token.hex())

    if ONE_PASS:
        print("M-Pin One Pass")
        if INPUT:
            PIN = int(input("Please enter PIN to authenticate:"))
        else:
            PIN = 1234
        epoch_time = get_time()
        if DEBUG:
            print("epoch_time %s" % epoch_time)

        # Client precomputation
        if MPIN_FULL:
            rtn, pc1, pc2 = precompute(token, hash_mpin_id)

        # Client MPIN
        rtn, x, u, ut, v, y = client(
            HASH_TYPE_MPIN, date, mpin_id, rng, None, PIN, token, time_permit, None, epoch_time)
        if rtn != 0:
            print("MPIN_CLIENT ERROR %s" % rtn)

        # Client sends Z=r.ID to Server
        if MPIN_FULL:
            rtn, r, Z = get_G1_multiple(rng, 1, None, hash_mpin_id)

        # Server MPIN
        rtn, HID, HTID, E, F, y2 = server(
            HASH_TYPE_MPIN, date, server_secret, u, ut, v, pID, None, epoch_time)
        if DEBUG:
            print("y2 ", y2.hex())
        if rtn != 0:
            print("ERROR: %s is not authenticated" % mpin_id)
            if PIN_ERROR:
                err = kangaroo(E, F)
                print("Client PIN error %d " % err)
            raise SystemExit(0)
        else:
            print("SUCCESS: %s is authenticated" % mpin_id)

        if date:
            prHID = HTID
        else:
            prHID = HID
            ut = None

        # Server sends T=w.ID to client
        if MPIN_FULL:
            rtn, w, T = get_G1_multiple(rng, 0, None, prHID)
            if rtn != 0:
                print("ERROR: Generating T %s" % rtn)

        if MPIN_FULL:
            HM = hash_all(HASH_TYPE_MPIN, hash_mpin_id, u, ut, v, y, r, w)

            rtn, client_aes_key = client_key(
                HASH_TYPE_MPIN, pc1, pc2, PIN, r, x, HM, T)
            if rtn != 0:
                print("ERROR: Generating client_aes_key %s" % rtn)
            print("Client AES Key: %s" % client_aes_key.hex())

            rtn, server_aes_key = server_key(
                HASH_TYPE_MPIN, Z, server_secret, w, HM, HID, u, ut)
            if rtn != 0:
                print("ERROR: Generating server_aes_key %s" % rtn)
            print("Server AES Key: %s" % server_aes_key.hex())

    else:
        print("M-Pin Three Pass")
        if INPUT:
            PIN = int(input("Please enter PIN to authenticate:"))
        else:
            PIN = 1234
        if MPIN_FULL:
            rtn, pc1, pc2 = precompute(token, hash_mpin_id)
            if rtn != 0:
                print("precompute(token, hash_mpin_id) ERROR %s" % rtn)

        # Client first pass
        rtn, x, u, ut, sec = client_1(
            HASH_TYPE_MPIN, date, mpin_id, rng, None, PIN, token, time_permit)
        if rtn != 0:
            print("client_1  ERROR %s" % rtn)
        if DEBUG:
            print("x: %s" % x.hex())

        # Server calculates H(ID) and H(T|H(ID)) (if time permits enabled),
        # and maps them to points on the curve HID and HTID resp.
        HID, HTID = server_1(HASH_TYPE_MPIN, date, pID)

        # Server generates Random number y and sends it to Client
        rtn, y = random_generate(rng)
        if rtn != 0:
            print("random_generate(rng) Error %s" % rtn)

        # Client second pass
        rtn, v = client_2(x, y, sec)
        if rtn != 0:
            print("client_2(x, y, sec) Error %s" % rtn)

        # Server second pass
        rtn, E, F = server_2(date, HID, HTID, y, server_secret, u, ut, v)
        if rtn != 0:
            print("ERROR: %s is not authenticated" % mpin_id)
            if PIN_ERROR:
                err = kangaroo(E, F)
                print("Client PIN error %d " % err)
            raise SystemExit(0)
        else:
            print("SUCCESS: %s is authenticated" % mpin_id)

        # Client sends Z=r.ID to Server
        if MPIN_FULL:
            rtn, r, Z = get_G1_multiple(rng, 1, None, hash_mpin_id)
            if rtn != 0:
                print("ERROR: Generating Z %s" % rtn)

        if date:
            prHID = HTID
        else:
            prHID = HID
            ut = None

        # Server sends T=w.ID to client
        if MPIN_FULL:
            rtn, w, T = get_G1_multiple(rng, 0, None, prHID)
            if rtn != 0:
                print("ERROR: Generating T %s" % rtn)

            HM = hash_all(HASH_TYPE_MPIN, hash_mpin_id, u, ut, v, y, r, w)

            rtn, client_aes_key = client_key(
                HASH_TYPE_MPIN, pc1, pc2, PIN, r, x, HM, T)
            if rtn != 0:
                print("ERROR: Generating client_aes_key %s" % rtn)
            print("Client AES Key: %s" % client_aes_key.hex())

            rtn, server_aes_key = server_key(
                HASH_TYPE_MPIN, Z, server_secret, w, HM, HID, u, ut)
            if rtn != 0:
                print("ERROR: Generating server_aes_key %s" % rtn)
            print("Server AES Key: %s" % server_aes_key.hex())

    if MPIN_FULL:
        plaintext = "A test message"
        print("message to encrypt: ", plaintext)
        header_hex = "1554a69ecbf04e507eb6985a234613246206c85f8af73e61ab6e2382a26f457d"
        header = bytes.fromhex(header_hex)
        iv_hex = "2b213af6b0edf6972bf996fb"
        iv = bytes.fromhex(iv_hex)
        ciphertext, tag = aes_gcm_encrypt(
            client_aes_key, iv, header, plaintext)
        print("ciphertext ", ciphertext.hex())
        print("tag1 ", tag.hex())

        plaintext2, tag2 = aes_gcm_decrypt(
            server_aes_key, iv, header, ciphertext)
        print("decrypted message: ", plaintext2)
        print("tag2 ", tag2.hex())
