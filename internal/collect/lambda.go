package collect

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/AWSHound/AWSHound/internal/model"
)

// LambdaCollector fetches AWS Lambda function data (region-scoped; see the package
// doc). Per region, Fetch paginates ListFunctions and enriches each function with its
// resource-based policy (GetPolicy) and function-URL config (GetFunctionUrlConfig),
// each left empty/nil when the function has none or the call is denied.
type LambdaCollector struct{}

// Service returns the collector's service identifier.
func (LambdaCollector) Service() string { return "lambda" }

// Fetch collects every Lambda function across the account's enabled regions. It
// mirrors LambdaCollector.fetch: list functions per region (stamping each with its
// region), then enrich each with its resource policy and URL config.
func (LambdaCollector) Fetch(ctx context.Context, s *Session) (any, error) {
	accountID, err := s.AccountID(ctx)
	if err != nil {
		return nil, err
	}

	perRegion, err := fanRegions(ctx, s, "lambda", func(ctx context.Context, region string) []model.LambdaFunction {
		client := lambda.NewFromConfig(s.regionCfg(region))

		var functions []model.LambdaFunction
		pager := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
		for pager.HasMorePages() {
			page, pageErr := pager.NextPage(ctx)
			if pageErr != nil {
				// One region's ListFunctions failure must not abort collection for
				// the rest of the account; skip the remainder of this region.
				break
			}
			for _, f := range page.Functions {
				fn := lambdaFunctionFromConfig(f, region)
				lambdaEnrich(ctx, client, &fn)
				functions = append(functions, fn)
			}
		}
		return functions
	})
	if err != nil {
		return nil, err
	}

	var functions []model.LambdaFunction
	for _, r := range perRegion {
		functions = append(functions, r...)
	}
	return &model.LambdaData{AccountId: accountID, Functions: functions}, nil
}

// lambdaFunctionFromConfig normalizes one ListFunctions FunctionConfiguration into
// the collected shape, stamping its region. Timeout/MemorySize are dereferenced to a
// plain int (0 when absent), which the node builder resolves to the Python defaults.
func lambdaFunctionFromConfig(f lambdatypes.FunctionConfiguration, region string) model.LambdaFunction {
	return model.LambdaFunction{
		FunctionName: aws.ToString(f.FunctionName),
		FunctionArn:  aws.ToString(f.FunctionArn),
		Runtime:      string(f.Runtime),
		Role:         aws.ToString(f.Role),
		Handler:      aws.ToString(f.Handler),
		CodeSize:     f.CodeSize,
		Description:  aws.ToString(f.Description),
		Timeout:      int(aws.ToInt32(f.Timeout)),
		MemorySize:   int(aws.ToInt32(f.MemorySize)),
		LastModified: aws.ToString(f.LastModified),
		CodeSha256:   aws.ToString(f.CodeSha256),
		KMSKeyArn:    aws.ToString(f.KMSKeyArn),
		Layers:       lambdaLayers(f.Layers),
		Region:       region,
	}
}

// lambdaLayers maps the SDK's function layers to the collected shape, keeping each
// layer's ARN (which the node emits) and size. Returns nil for a function with no
// layers, matching the absent Python key.
func lambdaLayers(layers []lambdatypes.Layer) []model.LambdaLayer {
	if len(layers) == 0 {
		return nil
	}
	out := make([]model.LambdaLayer, 0, len(layers))
	for _, l := range layers {
		out = append(out, model.LambdaLayer{
			Arn:      aws.ToString(l.Arn),
			CodeSize: l.CodeSize,
		})
	}
	return out
}

// lambdaEnrich adds a function's resource-based policy and URL config, addressing the
// function by ARN. Ports the Python collector's enrich closure: each sub-call is
// best-effort, so an absent policy/URL (ResourceNotFoundException) or a denied call
// simply leaves the field empty/nil rather than failing the function.
func lambdaEnrich(ctx context.Context, client *lambda.Client, fn *model.LambdaFunction) {
	// ListFunctions always supplies FunctionArn; guard the one impossible case
	// rather than falling back to the name.
	name := fn.FunctionArn
	if name == "" {
		return
	}

	if out, err := client.GetPolicy(ctx, &lambda.GetPolicyInput{
		FunctionName: aws.String(name),
	}); err == nil {
		fn.Policy = aws.ToString(out.Policy)
	}

	if out, err := client.GetFunctionUrlConfig(ctx, &lambda.GetFunctionUrlConfigInput{
		FunctionName: aws.String(name),
	}); err == nil {
		fn.FunctionUrlConfig = &model.LambdaFunctionUrlConfig{
			FunctionUrl:      aws.ToString(out.FunctionUrl),
			FunctionArn:      aws.ToString(out.FunctionArn),
			AuthType:         string(out.AuthType),
			CreationTime:     aws.ToString(out.CreationTime),
			LastModifiedTime: aws.ToString(out.LastModifiedTime),
			InvokeMode:       string(out.InvokeMode),
		}
	}

	// ListTags: ListFunctions does not return tags, so fetch them per function so
	// aws:ResourceTag/* conditions on lambda:* actions resolve. A successful call
	// records a non-nil map even when the function has no tags, so the evaluator
	// treats a missing tag as ABSENT (definitively no such tag) rather than UNKNOWN;
	// a denied/failed call leaves Tags nil so those conditions stay UNKNOWN.
	if out, err := client.ListTags(ctx, &lambda.ListTagsInput{
		Resource: aws.String(name),
	}); err == nil {
		if out.Tags == nil {
			fn.Tags = map[string]string{}
		} else {
			fn.Tags = out.Tags
		}
	}
}
