package store

import "github.com/AWSHound/AWSHound/internal/model"

// lambdaService is the resource-bag key for Lambda data. It matches
// LambdaCollector.Service().
const lambdaService = "lambda"

// IngestLambda stores a collected Lambda payload on the given account and interns
// every function ARN into the shared ARN universe. It is the in-memory analogue of
// AWSHound's add_lambda_data (core/models/_queries/awslambda.py): each function lands
// in the account's generic resource bag under lambdaService, keyed by its ARN, and
// that ARN is interned so the evaluator can resolve Lambda resource-pattern
// permissions. Functions without an ARN are skipped (they cannot be keyed and the
// node parser drops them anyway).
func IngestLambda(st *Store, accountID string, data *model.LambdaData) {
	if data == nil {
		return
	}
	acct := st.Account(accountID)
	for i := range data.Functions {
		fn := &data.Functions[i]
		if fn.FunctionArn == "" {
			continue
		}
		acct.PutResource(lambdaService, fn.FunctionArn, fn)
		st.ARN().Intern(fn.FunctionArn)
	}
}

// LambdaFunctionList returns the Lambda functions ingested on this account, ordered
// by ARN so the node builder produces diff-stable output.
func (a *Account) LambdaFunctionList() []*model.LambdaFunction {
	return listResources[model.LambdaFunction](a, lambdaService)
}
