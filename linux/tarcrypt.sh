#/bin/bash

DEBUG=1

usage ()
{
    cat << __EOF__
    Usage:  $0 [-e|--encrypt|-d|--decrypt] [-z|--gzip|-J|--xz] [-o output-file] [-p password] {input-file}

    tarcrypt is a handy combination of tar and aescrypt.  It is just a wrapper
    around those two fine programs that makes use of streams for efficiency.

    aescrypt is preffered since the resulting file is decryptable on any platform
    supported by aescrypt (there are clients for almost every platform), and
    a file encrypted on almost any other platform using aescrypt can be 
    decrypted with tarcrypt.

        -e | --encrypt : Puts tarcrypt in either encrypt or decrypt mode
        -d | --decrypt : Defaults to encrypt mode unless input-file ends in ".aes"

        -z | --gzip    : Used gzip or xz format as specified.  On decrypt jobs
        -J | --xz      : the format can be inferred from the extension.  Defaults
                       : to --xz if your version of tar supports it

        -o output-file : Optionally specify an output filename.  The default is
                       : to append .tar.{xz|gz}.aes for encrypting or to remove
                       : .tar.{xz|gz}.aes for decrypting

        -p password    : The password passed to aescrypt for encryption/decryption
                       : If not specified in the commnand, you'll be prompted for it
__EOF__
}

die ()
{
    echo "ERROR: $1" >&2
    exit 1
}

debug ()
{
    if (( DEBUG )); then
        echo "[DEBUG]: $1"
    fi
}


# make sure aescrypt is installed
which aescrypt >/dev/null 2>&1 || die "aescrypt is not installed (or is not in PATH)"
debug "aescrypt is installed at $(which aescrypt)"

ARGS="$@"
ENCRYPT=1
XZ=1
OF=""
IF=""
PASSWORD=""

# UO = User Override
UO_ENC=0
UO_XZ=0
UO_OF=0

for i in "$@"; do
    debug "Processing arg $i. ARGS is \"$ARGS\""

    if [[ "$i" =~ ^\-?\-e ]]; then
        ENCRYPT=1
        UO_ENC=1
        ARGS=$(echo $ARGS | sed -e 's/-e//g' | sed -e 's/--encrypt//g')
    fi

    if [[ "$i" =~ ^\-?\-d ]]; then
        ENCRYPT=0
        UO_ENC=1
        ARGS=$(echo $ARGS | sed -e 's/-d//g' | sed -e 's/--decrypt//g')
    fi

    if [[ "$i" =~ ^\-J ]] || [[ "$i" =~ ^\-\-xz ]]; then
        XZ=1
        UO_XZ=1
        ARGS=$(echo $ARGS | sed -e 's/-J//g' | sed -e 's/--xz//g')
    fi

    if [[ "$i" =~ ^\-z ]] || [[ "$i" =~ ^\-\-gzip ]]; then
        XZ=0
        UO_XZ=1
        ARGS=$(echo $ARGS | sed -e 's/-z//g' | sed -e 's/--gzip//g')
    fi

    if [[ "$i" =~ ^\-o ]]; then
        OF=$(echo "$@" | sed -e 's/.*\-o //g') # Remove everything up to the filename
        OF=$(echo "$OF" | sed -e 's/ .*//g')   # Remove everthing after the first slash
        ARGS=$(echo "$ARGS" | sed -e 's/-o//g' | sed -e "s/$OF//g")
        UO_OF=1
    fi

    if [[ "$i" =~ ^\-p ]]; then
        PASSWORD=$(echo "$@" | sed -e 's/.*\-p //g')     # Remove everything up to the filename
        PASSWORD=$(echo "$PASSWORD" | sed -e 's/ .*//g') # Remove everthing after the first slash
        ARGS=$(echo "$ARGS" | sed -e 's/-p//g' | sed -e "s/$PASSWORD//g")
    fi

    debug "Settings:  ECRYPT=$ENCRYPT - XZ=$XZ - OF=$OF - IF=$IF - PASSWORD=$PASSWORD"
    debug "Settings:  UO_ENC=$UO_ENC - UO_XZ=$UO_XZ - UO_OF=$UO_OF"
done

# The only thing left in ARGS should now be our input filename
IF="$ARGS"

[ -z "$IF" ] && die "No input filename specified"

INPUT_FILE=$(echo "$IF" | sed -e 's/ //g')

debug "Done processing args"
debug "Settings before inference:  ECRYPT=$ENCRYPT - XZ=$XZ - OF=$OF - IF=$IF - PASSWORD=$PASSWORD"

# if the user hasn't overriden the compression, pick one from input filename or default to xz
if ! (( UO_XZ )) && $(echo "$INPUT_FILE" | egrep "\.gz"); then
    XZ=0
    debug "Input file contains .gz extension and user did not specify compression. Assuming gzip"
fi
EXT="gz"
TAR_FLAG="z"
(( XZ )) && EXT="xz"
(( XZ )) && TAR_FLAG="J"

# if user hasn't overridden encryption, derive encryption mode
# if the input file contains ".aes" then decrypt.  Otherwise encrypt
if ! (( UO_ENC )) && $(echo "$INPUT_FILE" | egrep "\.aes$"); then
    debug "Input file contains .aes extension and user did not specify encryption. Assuming decryption"
    ENCRYPT=0
fi

if (( XZ )) && ! $(tar --help | egrep "\-\-xz" >/dev/null); then
    XZ=0
    echo "Your version of tar does not support xz.  Using gzip instead" >&2
fi

if [ -z "$OF" ]; then
    if (( ENCRYPT )); then
        # If we're encrypting, tack on a .tar.{xz|gz}.aes
        OUTPUT_FILE="${INPUT_FILE}.tar.${EXT}.aes"
    else
        # If we're decrypting, strip away .tar.{xz|gz}.aes or else append .decrypted
        TMP_OF=$(echo "${INPUT_FILE}" | sed -e "s/\.tar\.${EXT}.aes//g")
        if [ "$TMP_OF" = "$INPUT_FILE" ]; then
            TMP_OF="${INPUT_FILE}.decrypted"
        fi
        OUTPUT_FILE="$TMP_OF"
    fi
else
    OUTPUT_FILE="$OF"
    debug "Output file is user specified: $OUTPUT_FILE"
fi

OUTPUT_FILE=$(echo "$OUTPUT_FILE" | sed -e 's/ //g')

PASSARG=""
if [ -n "$PASSWORD" ]; then
    PASSARG="-p $PASSWORD"
fi

# If the user specified an output filename and we're decrypting, then we need to append an arg for tar
TAR_ARG_APP=""
if (( UO_OF )) && ! (( ENCRYPT )); then
    TAR_ARG_APP="--to-stdout >$OUTPUT_FILE"
fi

debug "ENCRYPT = $ENCRYPT"
debug "PASSARG = $PASSARG"
debug "TAR_FLAG = $TAR_FLAG"
debug "INPUT_FILE = $INPUT_FILE"
debug "OUTPUT_FILE = $OUTPUT_FILE"
debug "TAR_ARG_APP = $TAR_ARG_APP"

if (( ENCRYPT )); then
    echo "tar -c${TAR_FLAG}f - $INPUT_FILE | aescrypt -e $PASSARG - >${OUTPUT_FILE}"
else
    echo "aescrypt -d $PASSARG $INPUT_FILE -o - | tar -x${TAR_FLAG}f - $TAR_ARG_APP"
fi

