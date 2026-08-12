package graph

import "strings"

// IDDelimiter replaces the ARN ":" separator in emitted node ids.
const IDDelimiter = "_"

// EncodeID mirrors AWSHound's runtime/id_encoding.encode_id: every ":" in an
// ARN (or "*") becomes "_". It is applied ONLY at terminal serialization — the
// raw ARN is retained everywhere upstream (and in each node's "arn" property),
// so processors keep matching on real ARNs. The transform is idempotent-safe for
// the validator, which runs the same encode_id before lookup.
func EncodeID(id string) string { return strings.ReplaceAll(id, ":", IDDelimiter) }
