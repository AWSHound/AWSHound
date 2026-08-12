package store

import "testing"

// The index tags each interned ARN by its resource type, so the type-filtered
// join can pull the candidate-resource bitmap for an action's target type
// (§3.3/§7 of docs/authorization-tensor.md).
func TestArnIndexTypeBitmap(t *testing.T) {
	x := NewArnIndex()
	role1 := x.Intern("arn:aws:iam::111122223333:role/A")
	role2 := x.Intern("arn:aws:iam::111122223333:role/B")
	x.Intern("arn:aws:s3:::mybucket")

	roles := x.TypeBitmap("role")
	if !roles.Contains(role1) || !roles.Contains(role2) {
		t.Fatalf("role bitmap %v missing role ids %d,%d", roles.ToArray(), role1, role2)
	}
	if roles.GetCardinality() != 2 {
		t.Fatalf("role bitmap = %v, want exactly the two roles", roles.ToArray())
	}
	if x.TypeBitmap("bucket").GetCardinality() != 1 {
		t.Fatalf("bucket bitmap = %v, want one bucket", x.TypeBitmap("bucket").ToArray())
	}
	if x.TypeBitmap("nonesuch").GetCardinality() != 0 {
		t.Fatalf("unknown type should be empty, got %v", x.TypeBitmap("nonesuch").ToArray())
	}
}
