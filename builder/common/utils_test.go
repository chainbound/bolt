package common

import "testing"

func TestGenericFilter(t *testing.T) {
	slice := []*int{new(int), new(int), new(int), new(int)}
	for i := 0; i < len(slice); i++ {
		*slice[i] = i
	}

	Filter(&slice, func(el *int) bool {
		return el != nil
	})
	if len(slice) != 4 {
		t.Errorf("Filter failed")
	}
	Filter(&slice, func(el *int) bool {
		return *el%2 == 0
	})
	if len(slice) != 2 {
		t.Errorf("Filter failed")
	}
	Filter(&slice, func(el *int) bool {
		return el == nil
	})
	if len(slice) != 0 {
		t.Errorf("Filter failed")
	}
}
