package common

func Find[T any](slice []*T, predicate func(el *T) bool) *T {
	for _, el := range slice {
		if predicate(el) {
			return el
		}
	}
	return nil
}

func Filter[T any](slice *[]*T, predicate func(el *T) bool) {
	if slice == nil {
		return
	}

	for i := 0; i < len(*slice); i++ {
		el := (*slice)[i]
		if !predicate(el) {
			// Remove the element by slicing
			if i == len(*slice)-1 {
				*slice = (*slice)[:i]
			} else {
				*slice = append((*slice)[:i], (*slice)[i+1:]...)
			}
			i-- // Decrement index to adjust for the removed element
		}
	}
}

func Pop[T any](slice *[]*T) *T {
	if slice == nil || len(*slice) == 0 {
		return nil
	}
	el := (*slice)[len(*slice)-1]
	*slice = (*slice)[:len(*slice)-1]
	return el
}

func Shift[T any](slice *[]*T) *T {
	if slice == nil || len(*slice) == 0 {
		return nil
	}
	el := (*slice)[0]
	*slice = (*slice)[1:]
	return el
}
