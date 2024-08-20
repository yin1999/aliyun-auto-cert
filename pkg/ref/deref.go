package ref

func DerefOrDefault[T any](ptr *T) T {
	if ptr == nil {
		return *new(T)
	}
	return *ptr
}

func DerefOr[T any](ptr *T, defaultValue T) T {
	if ptr == nil {
		return defaultValue
	}
	return *ptr
}
