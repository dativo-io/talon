# Verdict of one `demo.sh run` from the agent's exit code, its transcript and
# the protected service's count deltas observed around the run. Sourced by
# demo.sh and tested offline by test-contract.sh with synthetic transcripts.
#
# run_verdict CODE TRANSCRIPT D_REFUNDS D_CUSTOMERS
#   prints one of: completed | resumed | rejected | pending | unresolved
#   or prints the violated expectation on stderr and returns 1.
#
# "completed" is a fresh dispatch: exactly one refund reached the service, a
# reviewer approved in this run or before the restart, the exact replay was
# refused. "resumed" is a restarted agent that found the refund already
# succeeded: the service must have seen NO new refund. Either way a forbidden
# deletion or an undenied adversarial probe is a failure.
run_verdict() {
  local code="$1" log="$2" d_refunds="$3" d_customers="$4"
  case "$code" in
    0)
      [[ "$d_customers" == 0 ]] || { echo "a forbidden deletion reached the protected service ($d_customers)" >&2; return 1; }
      grep -q 'ADVERSARIAL=denied' "$log" || { echo "the adversarial forbidden-action probe was not denied" >&2; return 1; }
      if grep -qE '^RESUMED=create_refund_request OPERATION=[^ ]+ STATUS=succeeded$' "$log"; then
        [[ "$d_refunds" == 0 ]] || { echo "a resumed run dispatched the refund again (observed $d_refunds)" >&2; return 1; }
        grep -q 'ATTEMPT=already_succeeded TOOL=create_refund_request' "$log" || { echo "the resumed refund was not reported as already succeeded" >&2; return 1; }
        echo resumed; return 0
      fi
      [[ "$d_refunds" == 1 ]] || { echo "expected exactly one refund dispatch, observed $d_refunds" >&2; return 1; }
      grep -qE '^APPROVAL=approved$|^RESUMED=create_refund_request OPERATION=[^ ]+ STATUS=authorized$' "$log" || { echo "completed without a reviewer approval in the transcript" >&2; return 1; }
      grep -q 'REPLAY=operation_already_succeeded' "$log" || { echo "replay safety was not demonstrated" >&2; return 1; }
      echo completed ;;
    2)
      [[ "$d_refunds" == 0 && "$d_customers" == 0 ]] || { echo "a rejected run produced downstream mutations (refunds=$d_refunds customers=$d_customers)" >&2; return 1; }
      echo rejected ;;
    3) echo pending ;;
    5) echo unresolved ;;
    *) echo "agent exited with $code (see $log)" >&2; return 1 ;;
  esac
}
