package model

// Lambda collected shapes (AWSHound's LambdaData / core/ingestion/awslambda.py; see
// the package doc for the shared conventions). ListFunctions supplies the
// configuration fields; the enrichment pass adds Policy (the raw resource-policy JSON
// string from GetPolicy) and FunctionUrlConfig (from GetFunctionUrlConfig), each
// present only when the function actually has one.

// LambdaData is the top-level collected shape for AWS Lambda: the account id plus
// every function discovered across the account's enabled regions.
type LambdaData struct {
	AccountId string           `json:"AccountId"`
	Functions []LambdaFunction `json:"Functions"`
}

// LambdaFunction is one Lambda function's ListFunctions configuration plus its
// enriched resource policy and function-URL config. It mirrors the per-function dict
// the Python collector builds.
//
//   - Region is stamped by the collector (the function's region); it is not returned
//     by ListFunctions.
//   - LastModified is the ISO-8601 string ListFunctions returns verbatim — the SDK
//     (like boto3) hands back a string here, so unlike the sibling services there is
//     no datetime to stringify.
//   - Policy holds the resource-based policy as the raw JSON string GetPolicy returns,
//     or "" when the function has none — matching the Python collector's
//     func["Policy"] = get_policy()["Policy"] (a string, never parsed at this layer).
//   - FunctionUrlConfig is nil when the function has no URL (the absent Python key); a
//     non-nil pointer is what marks has_function_url on the node.
//   - Tags is only ever populated from a re-ingested blob (ListFunctions does not
//     return tags), matching the node parser's defensive func.get("Tags") read.
type LambdaFunction struct {
	FunctionName      string                   `json:"FunctionName"`
	FunctionArn       string                   `json:"FunctionArn"`
	Runtime           string                   `json:"Runtime,omitempty"`
	Role              string                   `json:"Role,omitempty"`
	Handler           string                   `json:"Handler,omitempty"`
	CodeSize          int64                    `json:"CodeSize,omitempty"`
	Description       string                   `json:"Description,omitempty"`
	Timeout           int                      `json:"Timeout,omitempty"`
	MemorySize        int                      `json:"MemorySize,omitempty"`
	LastModified      string                   `json:"LastModified,omitempty"`
	CodeSha256        string                   `json:"CodeSha256,omitempty"`
	KMSKeyArn         string                   `json:"KMSKeyArn,omitempty"`
	Layers            []LambdaLayer            `json:"Layers,omitempty"`
	Region            string                   `json:"Region"`
	Policy            string                   `json:"Policy,omitempty"`
	FunctionUrlConfig *LambdaFunctionUrlConfig `json:"FunctionUrlConfig,omitempty"`
	Tags              map[string]string        `json:"Tags,omitempty"`
}

// LambdaLayer is one layer attached to a function (from ListFunctions' Layers). The
// node emits only the layer ARNs, but the collected shape keeps CodeSize for
// round-trip fidelity with the Python blob.
type LambdaLayer struct {
	Arn      string `json:"Arn"`
	CodeSize int64  `json:"CodeSize,omitempty"`
}

// LambdaFunctionUrlConfig is a function's URL configuration (from
// GetFunctionUrlConfig, with boto3's ResponseMetadata stripped). The node reads
// FunctionUrl and AuthType; the remaining scalars are captured so a re-ingested blob
// round-trips unchanged. AuthType "NONE" is what marks the function publicly
// accessible.
type LambdaFunctionUrlConfig struct {
	FunctionUrl      string `json:"FunctionUrl,omitempty"`
	FunctionArn      string `json:"FunctionArn,omitempty"`
	AuthType         string `json:"AuthType,omitempty"`
	CreationTime     string `json:"CreationTime,omitempty"`
	LastModifiedTime string `json:"LastModifiedTime,omitempty"`
	InvokeMode       string `json:"InvokeMode,omitempty"`
}
