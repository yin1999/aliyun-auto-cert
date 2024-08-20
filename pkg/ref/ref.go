package ref

func GetPointer[T any](v T) *T {
	return &v
}
