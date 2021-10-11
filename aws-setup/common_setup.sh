if [ ! "$1" ]; then
  echo 'Requires argument specifying environment' >&2
  echo 'For example:' >&2
  echo "  $0 production" >&2
  exit 2
fi

set -e

envname=$1
source envs/${envname}-envs.sh

document_file=$(mktemp)

# Check correct account
if [ ! "$(aws sts get-caller-identity | grep "\"Account\": \"${AWS_ACCT}\"")" ]; then
  echo "Authenticated with wrong AWS account - check the correct AWS profile is selected in envs/${envname}-envs.sh" > 2
  exit 3
fi

function gen_doc() {
  local infile=$1
  sed "s/AWS_ACCT/${AWS_ACCT}/g" defs/${infile} > ${document_file}
}
